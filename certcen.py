#!/usr/bin/env python3

import ctypes
import datetime
import ipaddress
import json
import os
import pathlib
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
from typing import Dict, List, Optional, Tuple

try:
    import cryptography
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    _CRYPTO_MAJOR = int(cryptography.__version__.split(".")[0])
except ImportError:
    print("\n  [!] Required dependency missing.")
    print("      Install with: pip install cryptography\n")
    sys.exit(1)


SYSTEM_PLATFORM = platform.system()
USER_HOME_DIR = pathlib.Path.home()
CA_BASE_DIR = USER_HOME_DIR / ".certcen"
CA_PRIVATE_KEY_FILE = CA_BASE_DIR / "root_ca.key"
CA_CERTIFICATE_FILE = CA_BASE_DIR / "root_ca.crt"
ISSUED_CERTS_BASE_DIR = CA_BASE_DIR / "issued"

CA_VALIDITY_DAYS = 3650
LEAF_CERT_VALIDITY_DAYS = 825
RSA_KEY_BITS = 4096
RSA_PUBLIC_EXPONENT = 65537

LINUX_TRUST_ANCHOR_REGISTRY = {
    pathlib.Path("/usr/local/share/ca-certificates"): [
        "update-ca-certificates"
    ],
    pathlib.Path("/etc/pki/ca-trust/source/anchors"): [
        "update-ca-trust", "extract"
    ],
    pathlib.Path("/etc/ca-certificates/trust-source/anchors"): [
        "trust", "extract-compat"
    ],
}

MACOS_SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"

COMMON_NAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9 ._\-]{0,61}[a-zA-Z0-9]$|^[a-zA-Z0-9]$"
)
DOMAIN_NAME_PATTERN = re.compile(
    r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    r"|^localhost$"
    r"|^[a-zA-Z0-9\-]{1,63}$"
)
COUNTRY_CODE_PATTERN = re.compile(r"^[A-Z]{2}$")

CERTCEN_BANNER = (
    "\033[36m"
    "\n"
    "   ██████╗███████╗██████╗ ████████╗ ██████╗███████╗███╗   ██╗\n"
    "  ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔════╝████╗  ██║\n"
    "  ██║     █████╗  ██████╔╝   ██║   ██║     █████╗  ██╔██╗ ██║\n"
    "  ██║     ██╔══╝  ██╔══██╗   ██║   ██║     ██╔══╝  ██║╚██╗██║\n"
    "  ╚██████╗███████╗██║  ██║   ██║   ╚██████╗███████╗██║ ╚████║\n"
    "   ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝╚══════╝╚═╝  ╚═══╝\n"
    "\033[0m"
    "\033[33m"
    "        Local Certificate Authority & SSL/TLS Generator\n"
    "                      · Zero Config\n"
    "\033[0m"
)

TERMINAL_WIDTH = 60
DIVIDER = "─" * TERMINAL_WIDTH


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _utc_delta(days: int) -> datetime.datetime:
    return _utc_now() + datetime.timedelta(days=days)


def _apply_validity_to_builder(
    builder: x509.CertificateBuilder,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
) -> x509.CertificateBuilder:
    return builder.not_valid_before(not_before).not_valid_after(not_after)


class InputSanitizer:

    @staticmethod
    def require_common_name(raw: str) -> str:
        stripped = raw.strip()
        if not stripped or not COMMON_NAME_PATTERN.match(stripped):
            raise ValueError(
                f"Invalid name '{stripped}'. Use 1–64 alphanumeric, "
                "space, dot, dash, or underscore characters."
            )
        return stripped

    @staticmethod
    def require_domain_or_hostname(raw: str) -> str:
        cleaned = raw.strip().lower()
        if not cleaned or not DOMAIN_NAME_PATTERN.match(cleaned):
            raise ValueError(
                f"Invalid domain or hostname: '{cleaned}'. "
                "Must be a valid FQDN, wildcard domain, or hostname."
            )
        return cleaned

    @staticmethod
    def require_ip_address(raw: str) -> str:
        try:
            return str(ipaddress.ip_address(raw.strip()))
        except ValueError:
            raise ValueError(f"Invalid IP address: '{raw.strip()}'")

    @staticmethod
    def require_country_code(raw: str) -> str:
        code = raw.strip().upper()
        if not COUNTRY_CODE_PATTERN.match(code):
            raise ValueError(f"Invalid country code '{code}'. Must be ISO 3166-1 alpha-2 (e.g. US).")
        return code

    @staticmethod
    def parse_san_list(raw: str) -> Tuple[List[str], List[str]]:
        entries = [e.strip() for e in raw.split(",") if e.strip()]
        validated_domains: List[str] = []
        validated_ips: List[str] = []

        for entry in entries:
            try:
                validated_ips.append(InputSanitizer.require_ip_address(entry))
                continue
            except ValueError:
                pass
            try:
                validated_domains.append(InputSanitizer.require_domain_or_hostname(entry))
            except ValueError:
                raise ValueError(
                    f"Cannot classify '{entry}' as a valid domain or IP address."
                )

        return validated_domains, validated_ips


class CertificateAuthorityManager:

    def __init__(self):
        CA_BASE_DIR.mkdir(parents=True, exist_ok=True)
        ISSUED_CERTS_BASE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            CA_BASE_DIR.chmod(0o700)
        except OSError:
            pass

    def ca_exists(self) -> bool:
        return CA_PRIVATE_KEY_FILE.exists() and CA_CERTIFICATE_FILE.exists()

    def generate_root_ca(
        self,
        common_name: str,
        org_name: str,
        country_code: str,
    ) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:

        ca_private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=RSA_KEY_BITS,
            backend=default_backend(),
        )

        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country_code),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = _utc_now()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(ca_subject)
        builder = builder.issuer_name(ca_subject)
        builder = builder.public_key(ca_private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = _apply_validity_to_builder(builder, now, _utc_delta(CA_VALIDITY_DAYS))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False,
        )

        ca_certificate = builder.sign(ca_private_key, hashes.SHA256(), default_backend())
        self._write_ca_to_disk(ca_private_key, ca_certificate)
        return ca_private_key, ca_certificate

    def load_existing_ca(self) -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
        raw_key = CA_PRIVATE_KEY_FILE.read_bytes()
        raw_cert = CA_CERTIFICATE_FILE.read_bytes()
        loaded_key = serialization.load_pem_private_key(
            raw_key, password=None, backend=default_backend()
        )
        loaded_cert = x509.load_pem_x509_certificate(raw_cert, default_backend())
        return loaded_key, loaded_cert

    def _write_ca_to_disk(
        self,
        private_key: rsa.RSAPrivateKey,
        certificate: x509.Certificate,
    ) -> None:
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)

        CA_PRIVATE_KEY_FILE.write_bytes(key_pem)
        try:
            CA_PRIVATE_KEY_FILE.chmod(0o600)
        except OSError:
            pass

        CA_CERTIFICATE_FILE.write_bytes(cert_pem)
        try:
            CA_CERTIFICATE_FILE.chmod(0o644)
        except OSError:
            pass


class SystemTrustInstaller:

    def __init__(self, ca_cert_path: pathlib.Path):
        self.ca_cert_path = ca_cert_path

    def install(self) -> bool:
        dispatch = {
            "Linux": self._install_linux,
            "Darwin": self._install_macos,
            "Windows": self._install_windows,
        }
        handler = dispatch.get(SYSTEM_PLATFORM)
        if not handler:
            print(f"  [!] Unsupported platform: {SYSTEM_PLATFORM}")
            return False
        return handler()

    def _is_root_unix(self) -> bool:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False

    def _run_privileged(self, command: List[str]) -> Tuple[bool, str]:
        if self._is_root_unix():
            full_cmd = command
        else:
            full_cmd = ["sudo"] + command

        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode == 0, result.stderr
        except FileNotFoundError as exc:
            return False, str(exc)
        except subprocess.TimeoutExpired:
            return False, "Command timed out"

    def _install_linux(self) -> bool:
        for anchor_dir, update_cmd in LINUX_TRUST_ANCHOR_REGISTRY.items():
            if not anchor_dir.exists():
                continue

            cert_filename = "certcen-root-ca.crt"
            dest_path = anchor_dir / cert_filename

            copy_ok, copy_err = self._run_privileged(
                ["cp", str(self.ca_cert_path), str(dest_path)]
            )
            if not copy_ok:
                print(f"  [!] Could not copy to {anchor_dir}: {copy_err}")
                continue

            chmod_ok, _ = self._run_privileged(["chmod", "644", str(dest_path)])

            update_ok, update_err = self._run_privileged(update_cmd)
            if update_ok:
                print(f"  [✓] Installed to {anchor_dir}")
                print(f"  [✓] Trust store updated via: {' '.join(update_cmd)}")
                return True
            else:
                print(f"  [!] Update command failed: {update_err}")

        print("  [!] No supported Linux CA anchor directory found.")
        return False

    def _install_macos(self) -> bool:
        install_cmd = [
            "security", "add-trusted-cert",
            "-d",
            "-r", "trustRoot",
            "-k", MACOS_SYSTEM_KEYCHAIN,
            str(self.ca_cert_path),
        ]
        ok, err = self._run_privileged(install_cmd)
        if ok:
            print(f"  [✓] Installed to macOS System Keychain")
        else:
            print(f"  [!] macOS Keychain installation failed: {err}")
        return ok

    def _is_windows_admin(self) -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _install_windows(self) -> bool:
        if not self._is_windows_admin():
            print("  [!] Windows requires Administrator privileges.")
            print("  [>] Re-run this script as Administrator.")
            return False

        cmd = ["certutil", "-addstore", "-f", "Root", str(self.ca_cert_path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print("  [✓] Installed to Windows Certificate Store (Root)")
                return True
            else:
                print(f"  [!] certutil failed: {result.stderr}")
                return False
        except FileNotFoundError:
            print("  [!] certutil not found. Is this Windows?")
            return False


class DomainCertificateGenerator:

    def __init__(self, ca_manager: CertificateAuthorityManager):
        self.ca_manager = ca_manager

    def generate(
        self,
        common_name: str,
        san_domains: List[str],
        san_ips: List[str],
        output_dir: pathlib.Path,
    ) -> Tuple[pathlib.Path, pathlib.Path]:

        ca_key, ca_cert = self.ca_manager.load_existing_ca()

        leaf_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=RSA_KEY_BITS,
            backend=default_backend(),
        )

        ordered_domains: List[str] = []
        seen: set = set()
        for d in [common_name] + san_domains:
            if d not in seen:
                ordered_domains.append(d)
                seen.add(d)

        san_entries: List[x509.GeneralName] = []
        for domain in ordered_domains:
            san_entries.append(x509.DNSName(domain))
        for ip_str in san_ips:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        now = _utc_now()

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.public_key(leaf_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = _apply_validity_to_builder(builder, now, _utc_delta(LEAF_CERT_VALIDITY_DAYS))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )

        leaf_cert = builder.sign(ca_key, hashes.SHA256(), default_backend())

        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            output_dir.chmod(0o700)
        except OSError:
            pass

        safe_stem = re.sub(r"[^a-zA-Z0-9_\-]", "_", common_name)
        cert_file = output_dir / f"{safe_stem}.crt"
        key_file = output_dir / f"{safe_stem}.key"

        cert_file.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
        try:
            cert_file.chmod(0o644)
        except OSError:
            pass

        key_file.write_bytes(
            leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        try:
            key_file.chmod(0o600)
        except OSError:
            pass

        return cert_file, key_file


class DevServerDetector:

    DJANGO_MANAGE_MARKERS = ["django", "DJANGO_SETTINGS_MODULE", "execute_from_command_line"]
    FLASK_CODE_MARKERS = ["from flask import", "import flask", "Flask(__name__)"]
    FLASK_RUN_MARKERS = ["app.run(", "application.run("]
    EXPRESS_MARKERS = ["express()", "require('express')", 'require("express")']
    HTTPS_MARKERS = ["require('https')", 'require("https")', "createServer"]

    def __init__(self, search_root: pathlib.Path):
        self.search_root = search_root

    def detect_all(self) -> Dict[str, List[pathlib.Path]]:
        return {
            "django": self._locate_django_settings(),
            "flask": self._locate_flask_apps(),
            "nodejs_express": self._locate_node_express(),
            "nodejs_https": self._locate_node_https(),
            "nginx": self._locate_nginx_configs(),
            "apache": self._locate_apache_configs(),
            "dotenv": self._locate_dotenv_files(),
        }

    def _safe_glob(self, pattern: str) -> List[pathlib.Path]:
        try:
            return list(self.search_root.glob(pattern))
        except (PermissionError, OSError):
            return []

    def _file_has_marker(self, path: pathlib.Path, markers: List[str]) -> bool:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            return any(m in text for m in markers)
        except (OSError, PermissionError):
            return False

    def _locate_django_settings(self) -> List[pathlib.Path]:
        candidates = (
            self._safe_glob("settings.py")
            + self._safe_glob("*/settings.py")
            + self._safe_glob("*/*/settings.py")
            + self._safe_glob("*/*/*/settings.py")
        )
        confirmed: List[pathlib.Path] = []
        for settings_file in candidates:
            manage = settings_file.parent.parent / "manage.py"
            if manage.exists() and self._file_has_marker(manage, self.DJANGO_MANAGE_MARKERS):
                confirmed.append(settings_file)
        return confirmed

    def _locate_flask_apps(self) -> List[pathlib.Path]:
        py_files = (
            self._safe_glob("*.py")
            + self._safe_glob("*/*.py")
            + self._safe_glob("*/*/*.py")
        )
        confirmed: List[pathlib.Path] = []
        for py_file in py_files:
            if (
                self._file_has_marker(py_file, self.FLASK_CODE_MARKERS)
                and self._file_has_marker(py_file, self.FLASK_RUN_MARKERS)
            ):
                confirmed.append(py_file)
        return confirmed[:5]

    def _locate_node_express(self) -> List[pathlib.Path]:
        js_files = (
            self._safe_glob("*.js")
            + self._safe_glob("src/*.js")
            + self._safe_glob("server/*.js")
        )
        return [f for f in js_files if self._file_has_marker(f, self.EXPRESS_MARKERS)][:5]

    def _locate_node_https(self) -> List[pathlib.Path]:
        package_files = (
            self._safe_glob("package.json")
            + self._safe_glob("*/package.json")
            + self._safe_glob("*/*/package.json")
        )
        confirmed: List[pathlib.Path] = []
        for pkg in package_files:
            try:
                data = json.loads(pkg.read_text(encoding="utf-8"))
                if isinstance(data.get("dependencies"), dict) or isinstance(data.get("scripts"), dict):
                    confirmed.append(pkg)
            except (json.JSONDecodeError, OSError):
                continue
        return confirmed

    def _locate_nginx_configs(self) -> List[pathlib.Path]:
        standard = [
            pathlib.Path("/etc/nginx/nginx.conf"),
            pathlib.Path("/etc/nginx/conf.d/default.conf"),
            pathlib.Path("/usr/local/etc/nginx/nginx.conf"),
            pathlib.Path("/opt/homebrew/etc/nginx/nginx.conf"),
        ]
        found = [p for p in standard if p.exists()]
        found += self._safe_glob("*.conf") + self._safe_glob("nginx/*.conf")
        return list({p: None for p in found}.keys())

    def _locate_apache_configs(self) -> List[pathlib.Path]:
        standard = [
            pathlib.Path("/etc/apache2/apache2.conf"),
            pathlib.Path("/etc/httpd/conf/httpd.conf"),
            pathlib.Path("/usr/local/etc/httpd/httpd.conf"),
            pathlib.Path("/etc/apache2/sites-enabled/000-default.conf"),
            pathlib.Path("/opt/homebrew/etc/httpd/httpd.conf"),
        ]
        return [p for p in standard if p.exists()]

    def _locate_dotenv_files(self) -> List[pathlib.Path]:
        candidates = (
            self._safe_glob(".env")
            + self._safe_glob("*/.env")
            + self._safe_glob(".env.development")
            + self._safe_glob(".env.local")
        )
        return candidates[:5]


class DevServerConfigurator:

    CERTCEN_TAG = "# CertCen SSL"

    def __init__(self, cert_path: pathlib.Path, key_path: pathlib.Path):
        self.cert_path = cert_path
        self.key_path = key_path

    def configure_detected(
        self, detections: Dict[str, List[pathlib.Path]]
    ) -> Dict[str, List[Tuple[pathlib.Path, bool]]]:
        results: Dict[str, List[Tuple[pathlib.Path, bool]]] = {}

        config_dispatch = {
            "django": self._configure_django_settings,
            "flask": self._configure_flask_application,
            "nodejs_express": self._configure_express_server,
            "nodejs_https": self._configure_node_package,
            "nginx": self._configure_nginx_vhost,
            "apache": self._configure_apache_vhost,
            "dotenv": self._configure_dotenv_ssl,
        }

        for server_type, paths in detections.items():
            if not paths:
                continue
            handler = config_dispatch.get(server_type)
            if not handler:
                continue
            results[server_type] = [(p, handler(p)) for p in paths]

        return results

    def _already_patched(self, target: pathlib.Path) -> bool:
        try:
            return self.CERTCEN_TAG in target.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return False

    def _safe_append(self, target: pathlib.Path, snippet: str) -> bool:
        if self._already_patched(target):
            return True
        try:
            backup = target.with_suffix(target.suffix + ".certcen.bak")
            backup.write_bytes(target.read_bytes())
            with target.open("a", encoding="utf-8") as fh:
                fh.write(snippet)
            return True
        except (OSError, PermissionError):
            return False

    def _safe_write_new(self, target: pathlib.Path, content: str) -> bool:
        try:
            target.write_text(content, encoding="utf-8")
            return True
        except (OSError, PermissionError):
            return False

    def _configure_django_settings(self, settings_file: pathlib.Path) -> bool:
        snippet = textwrap.dedent(f"""

            {self.CERTCEN_TAG} (auto-configured by CertCen)
            CERTCEN_SSL_CERT = r'{self.cert_path}'
            CERTCEN_SSL_KEY  = r'{self.key_path}'
            # Enable HTTPS in development with django-extensions:
            #   pip install django-extensions Werkzeug pyOpenSSL
            #   python manage.py runserver_plus --cert-file CERTCEN_SSL_CERT --key-file CERTCEN_SSL_KEY
        """)
        return self._safe_append(settings_file, snippet)

    def _configure_flask_application(self, app_file: pathlib.Path) -> bool:
        snippet = textwrap.dedent(f"""

            {self.CERTCEN_TAG} (auto-configured by CertCen)
            _CERTCEN_SSL_CONTEXT = (r'{self.cert_path}', r'{self.key_path}')
            # To enable HTTPS, change app.run() to:
            #   app.run(ssl_context=_CERTCEN_SSL_CONTEXT, host='0.0.0.0', port=5443)
        """)
        return self._safe_append(app_file, snippet)

    def _configure_express_server(self, server_file: pathlib.Path) -> bool:
        snippet = textwrap.dedent(f"""

            // {self.CERTCEN_TAG} (auto-configured by CertCen)
            // To enable HTTPS replace your http server with:
            // const https = require('https');
            // const fs = require('fs');
            // const _certcenOptions = {{
            //   key:  fs.readFileSync(r'{self.key_path}'),
            //   cert: fs.readFileSync(r'{self.cert_path}')
            // }};
            // https.createServer(_certcenOptions, app).listen(443);
        """)
        return self._safe_append(server_file, snippet)

    def _configure_node_package(self, package_json: pathlib.Path) -> bool:
        ssl_config_file = package_json.parent / "certcen.ssl.json"
        config_content = json.dumps(
            {
                "_comment": "Generated by CertCen. Import paths in your HTTPS server setup.",
                "certcen": {
                    "cert": str(self.cert_path),
                    "key": str(self.key_path),
                    "ca": str(CA_CERTIFICATE_FILE),
                },
            },
            indent=2,
        )
        return self._safe_write_new(ssl_config_file, config_content)

    def _configure_nginx_vhost(self, nginx_conf: pathlib.Path) -> bool:
        snippet = textwrap.dedent(f"""

            # {self.CERTCEN_TAG} — generated by CertCen
            # Add the following directives inside your server {{ }} block:
            #
            #   listen 443 ssl;
            #   ssl_certificate      {self.cert_path};
            #   ssl_certificate_key  {self.key_path};
            #   ssl_protocols        TLSv1.2 TLSv1.3;
            #   ssl_ciphers          HIGH:!aNULL:!MD5;
        """)
        return self._safe_append(nginx_conf, snippet)

    def _configure_apache_vhost(self, apache_conf: pathlib.Path) -> bool:
        snippet = textwrap.dedent(f"""

            # {self.CERTCEN_TAG} — generated by CertCen
            # Add a VirtualHost block or update an existing one:
            #
            # <VirtualHost *:443>
            #   SSLEngine on
            #   SSLCertificateFile      {self.cert_path}
            #   SSLCertificateKeyFile   {self.key_path}
            # </VirtualHost>
        """)
        return self._safe_append(apache_conf, snippet)

    def _configure_dotenv_ssl(self, dotenv_file: pathlib.Path) -> bool:
        snippet = textwrap.dedent(f"""

            # {self.CERTCEN_TAG} (auto-configured by CertCen)
            SSL_CERT_FILE={self.cert_path}
            SSL_KEY_FILE={self.key_path}
            CA_CERT_FILE={CA_CERTIFICATE_FILE}
        """)
        return self._safe_append(dotenv_file, snippet)


class CertCenCLI:

    def __init__(self):
        self.ca_manager = CertificateAuthorityManager()
        self.trust_installer = SystemTrustInstaller(CA_CERTIFICATE_FILE)
        self.cert_generator = DomainCertificateGenerator(self.ca_manager)
        self.validator = InputSanitizer()

    def start(self) -> None:
        print(CERTCEN_BANNER)
        print(f"  Platform : {SYSTEM_PLATFORM}  (cryptography {cryptography.__version__})")
        print(f"  CA Store : {CA_BASE_DIR}")
        print()

        while True:
            self._render_menu()
            choice = input("\n  > ").strip()
            action_map = {
                "1": self._action_setup_ca,
                "2": self._action_generate_certificate,
                "3": self._action_detect_and_configure,
                "4": self._action_show_status,
                "5": self._action_export_ca_cert,
                "6": self._action_revoke_and_clean,
                "0": self._action_exit,
            }
            handler = action_map.get(choice)
            if handler:
                handler()
            else:
                print("  [!] Invalid choice.")

    def _render_menu(self) -> None:
        ca_label = (
            "\033[32m[ACTIVE]\033[0m"
            if self.ca_manager.ca_exists()
            else "\033[31m[NOT CONFIGURED]\033[0m"
        )
        print(f"\n  {DIVIDER}")
        print(f"  Root CA Status: {ca_label}")
        print(f"  {DIVIDER}")
        print("   1  Setup / Regenerate Root CA")
        print("   2  Generate Domain Certificate")
        print("   3  Detect & Auto-Configure Dev Servers")
        print("   4  Show CA Info & Issued Certificates")
        print("   5  Export CA Certificate (for manual import)")
        print("   6  Clean Issued Certificate")
        print("   0  Exit")
        print(f"  {DIVIDER}")

    def _ask(self, prompt: str, default: str = "") -> str:
        display = f"  {prompt}"
        if default:
            display += f" [{default}]"
        display += ": "
        response = input(display).strip()
        return response if response else default

    def _confirm(self, prompt: str, default_yes: bool = True) -> bool:
        hint = "Y/n" if default_yes else "y/N"
        response = self._ask(f"{prompt} ({hint})", "y" if default_yes else "n")
        return response.lower() in ("y", "yes")

    def _action_exit(self) -> None:
        print("\n  Goodbye.\n")
        sys.exit(0)

    def _action_setup_ca(self) -> None:
        print(f"\n  {DIVIDER}")
        print("   ROOT CA SETUP")
        print(f"  {DIVIDER}")

        if self.ca_manager.ca_exists():
            if not self._confirm("Root CA already exists. Regenerate it?", default_yes=False):
                print("  Keeping existing Root CA.")
                return

        raw_cn = self._ask("CA Common Name", "CertCen Development Root CA")
        raw_org = self._ask("Organization Name", "CertCen Local PKI")
        raw_country = self._ask("Country Code (ISO 3166-1 alpha-2)", "US")

        try:
            cn = self.validator.require_common_name(raw_cn)
            org = self.validator.require_common_name(raw_org)
            country = self.validator.require_country_code(raw_country)
        except ValueError as exc:
            print(f"  [!] Validation error: {exc}")
            return

        print(f"\n  Generating {RSA_KEY_BITS}-bit RSA root CA key...")
        print("  (This may take a few seconds.)")

        try:
            self.ca_manager.generate_root_ca(cn, org, country)
        except Exception as exc:
            print(f"  [!] CA generation failed: {exc}")
            return

        print(f"\n  [✓] Root CA private key : {CA_PRIVATE_KEY_FILE}")
        print(f"  [✓] Root CA certificate  : {CA_CERTIFICATE_FILE}")
        print(f"  [✓] Valid for {CA_VALIDITY_DAYS} days ({CA_VALIDITY_DAYS // 365} years)")

        if self._confirm("\n  Install CA into system trust store?"):
            print(f"\n  Installing on {SYSTEM_PLATFORM}...")
            ok = self.trust_installer.install()
            if ok:
                print("  [✓] Browsers and tools on this machine will now trust certs from this CA.")
            else:
                print(f"  [!] Automatic installation failed.")
                print(f"  [>] Manually trust: {CA_CERTIFICATE_FILE}")

    def _action_generate_certificate(self) -> None:
        print(f"\n  {DIVIDER}")
        print("   GENERATE DOMAIN CERTIFICATE")
        print(f"  {DIVIDER}")

        if not self.ca_manager.ca_exists():
            print("  [!] Root CA is not set up. Run option 1 first.")
            return

        raw_cn = self._ask("Primary domain / hostname", "localhost")
        try:
            common_name = self.validator.require_domain_or_hostname(raw_cn)
        except ValueError as exc:
            print(f"  [!] {exc}")
            return

        default_sans = f"{common_name},127.0.0.1,::1"
        raw_sans = self._ask("Additional SANs (comma-separated)", default_sans)

        try:
            san_domains, san_ips = self.validator.parse_san_list(raw_sans)
        except ValueError as exc:
            print(f"  [!] {exc}")
            return

        all_domains = list(dict.fromkeys([common_name] + san_domains))

        print(f"\n  Domains : {', '.join(all_domains)}")
        if san_ips:
            print(f"  IPs     : {', '.join(san_ips)}")
        print(f"  Valid   : {LEAF_CERT_VALIDITY_DAYS} days")
        print(f"  Key     : RSA {RSA_KEY_BITS}-bit")

        if not self._confirm("\n  Generate certificate?"):
            print("  Cancelled.")
            return

        safe_dir = re.sub(r"[^a-zA-Z0-9_\-]", "_", common_name)
        output_dir = ISSUED_CERTS_BASE_DIR / safe_dir

        print("\n  Generating...")

        try:
            cert_path, key_path = self.cert_generator.generate(
                common_name, all_domains, san_ips, output_dir
            )
        except Exception as exc:
            print(f"  [!] Certificate generation failed: {exc}")
            return

        print(f"\n  [✓] Certificate : {cert_path}")
        print(f"  [✓] Private Key  : {key_path}")

        if self._confirm("\n  Auto-configure detected dev servers?"):
            self._run_server_detection_and_configure(cert_path, key_path)

    def _run_server_detection_and_configure(
        self,
        cert_path: pathlib.Path,
        key_path: pathlib.Path,
        search_root: Optional[pathlib.Path] = None,
    ) -> None:
        if search_root is None:
            search_root = pathlib.Path.cwd()

        print(f"\n  Scanning: {search_root}")
        detector = DevServerDetector(search_root)
        detections = detector.detect_all()

        total = sum(len(v) for v in detections.values())
        if total == 0:
            print("  No recognized dev server configurations found.")
            return

        print()
        for server_type, paths in detections.items():
            if paths:
                print(f"  {server_type.upper()} — {len(paths)} file(s):")
                for p in paths:
                    print(f"    · {p}")

        if not self._confirm("\n  Apply SSL configuration patches?"):
            print("  Skipped.")
            return

        configurator = DevServerConfigurator(cert_path, key_path)
        results = configurator.configure_detected(detections)

        print()
        for server_type, file_results in results.items():
            for file_path, success in file_results:
                status_icon = "[✓]" if success else "[!]"
                label = "patched" if success else "FAILED"
                print(f"  {status_icon} {server_type}: {file_path.name} — {label}")

    def _action_detect_and_configure(self) -> None:
        print(f"\n  {DIVIDER}")
        print("   DETECT & CONFIGURE DEV SERVERS")
        print(f"  {DIVIDER}")

        if not self.ca_manager.ca_exists():
            print("  [!] Root CA not configured. Generate a certificate first.")
            return

        issued = (
            list(ISSUED_CERTS_BASE_DIR.glob("**/*.crt"))
            if ISSUED_CERTS_BASE_DIR.exists()
            else []
        )

        if not issued:
            print("  [!] No issued certificates found. Generate one with option 2.")
            return

        raw_search = self._ask("Directory to scan", str(pathlib.Path.cwd()))
        search_root = pathlib.Path(raw_search).resolve()

        if not search_root.is_dir():
            print(f"  [!] Not a directory: {search_root}")
            return

        print("\n  Available certificates:")
        for idx, cert_file in enumerate(issued, 1):
            print(f"  {idx}. {cert_file.stem}")

        raw_choice = self._ask("Select certificate number", "1")
        try:
            selected_idx = int(raw_choice) - 1
            if not 0 <= selected_idx < len(issued):
                raise ValueError()
        except ValueError:
            print("  [!] Invalid selection.")
            return

        selected_cert = issued[selected_idx]
        selected_key = selected_cert.with_suffix(".key")

        if not selected_key.exists():
            print(f"  [!] Key file missing: {selected_key}")
            return

        self._run_server_detection_and_configure(selected_cert, selected_key, search_root)

    def _action_show_status(self) -> None:
        print(f"\n  {DIVIDER}")
        print("   CA STATUS & ISSUED CERTIFICATES")
        print(f"  {DIVIDER}")

        if not self.ca_manager.ca_exists():
            print("  Root CA: Not configured")
            return

        try:
            _, ca_cert = self.ca_manager.load_existing_ca()
        except Exception as exc:
            print(f"  [!] Could not load CA: {exc}")
            return

        try:
            subject_str = ca_cert.subject.rfc4514_string()
        except Exception:
            subject_str = str(ca_cert.subject)

        if _CRYPTO_MAJOR >= 42:
            valid_from = ca_cert.not_valid_before_utc
            valid_to = ca_cert.not_valid_after_utc
            days_remaining = (valid_to - _utc_now()).days
        else:
            valid_from = ca_cert.not_valid_before
            valid_to = ca_cert.not_valid_after
            days_remaining = (valid_to - datetime.datetime.utcnow()).days

        print(f"\n  Subject      : {subject_str}")
        print(f"  Serial       : {hex(ca_cert.serial_number)}")
        print(f"  Valid From   : {valid_from.strftime('%Y-%m-%d')}")
        print(f"  Valid To     : {valid_to.strftime('%Y-%m-%d')} ({days_remaining} days left)")
        print(f"  Key File     : {CA_PRIVATE_KEY_FILE}")
        print(f"  Cert File    : {CA_CERTIFICATE_FILE}")

        issued = (
            list(ISSUED_CERTS_BASE_DIR.glob("**/*.crt"))
            if ISSUED_CERTS_BASE_DIR.exists()
            else []
        )

        print(f"\n  Issued Leaf Certificates: {len(issued)}")
        for cert_file in issued:
            try:
                leaf = x509.load_pem_x509_certificate(cert_file.read_bytes(), default_backend())
                if _CRYPTO_MAJOR >= 42:
                    exp = leaf.not_valid_after_utc
                else:
                    exp = leaf.not_valid_after
                san_ext = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                dns_names = san_ext.value.get_values_for_type(x509.DNSName)
                dns_summary = ", ".join(dns_names[:3])
                print(f"    · {cert_file.stem} | expires {exp.strftime('%Y-%m-%d')} | {dns_summary}")
            except Exception:
                print(f"    · {cert_file.stem} (unable to parse)")

    def _action_export_ca_cert(self) -> None:
        print(f"\n  {DIVIDER}")
        print("   EXPORT CA CERTIFICATE")
        print(f"  {DIVIDER}")

        if not self.ca_manager.ca_exists():
            print("  [!] Root CA not configured.")
            return

        export_path = self._ask(
            "Export path", str(pathlib.Path.cwd() / "certcen-root-ca.crt")
        )
        target = pathlib.Path(export_path)

        try:
            shutil.copy2(CA_CERTIFICATE_FILE, target)
            print(f"\n  [✓] CA certificate exported to: {target}")
            print()
            print("  Import instructions:")
            print("    Chrome/Edge  : Settings → Privacy → Manage Certificates → Import")
            print("    Firefox      : about:preferences#privacy → View Certificates → Import")
            print("    macOS        : double-click the .crt file, then set Trust to 'Always Trust'")
            print("    Windows      : double-click → Install Certificate → Local Machine → Trusted Root")
            print("    Linux (curl) : sudo cp <file> /usr/local/share/ca-certificates/ && sudo update-ca-certificates")
        except (OSError, shutil.Error) as exc:
            print(f"  [!] Export failed: {exc}")

    def _action_revoke_and_clean(self) -> None:
        print(f"\n  {DIVIDER}")
        print("   REMOVE ISSUED CERTIFICATE")
        print(f"  {DIVIDER}")

        issued = (
            list(ISSUED_CERTS_BASE_DIR.glob("**/*.crt"))
            if ISSUED_CERTS_BASE_DIR.exists()
            else []
        )

        if not issued:
            print("  No issued certificates to remove.")
            return

        for idx, cert_file in enumerate(issued, 1):
            print(f"  {idx}. {cert_file.stem}")

        raw_choice = self._ask("Select certificate to remove (0 to cancel)", "0")
        try:
            choice = int(raw_choice)
        except ValueError:
            print("  Invalid input.")
            return

        if choice == 0:
            return

        if not 1 <= choice <= len(issued):
            print("  [!] Out of range.")
            return

        target_cert = issued[choice - 1]
        target_key = target_cert.with_suffix(".key")
        target_dir = target_cert.parent

        if not self._confirm(f"Permanently delete {target_cert.stem}?", default_yes=False):
            return

        removed = []
        for f in [target_cert, target_key]:
            if f.exists():
                try:
                    f.unlink()
                    removed.append(f.name)
                except OSError as exc:
                    print(f"  [!] Could not delete {f.name}: {exc}")

        try:
            if target_dir != ISSUED_CERTS_BASE_DIR and not any(target_dir.iterdir()):
                target_dir.rmdir()
        except OSError:
            pass

        for name in removed:
            print(f"  [✓] Removed: {name}")


def main() -> None:
    cli = CertCenCLI()
    try:
        cli.start()
    except KeyboardInterrupt:
        print("\n\n  Interrupted. Goodbye.\n")
        sys.exit(0)

if __name__ == "__main__":
    main()
