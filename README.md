# Overview

- It handles everything from CA generation to automatic trust-store installation across Linux, macOS, and Windows, plus leaf certificate creation with proper SANs and basic auto-configuration for common dev servers.
  
- Automatic trust-store installation on Linux (multiple distro paths), macOS System Keychain, and Windows Root store.
- Built-in detector that finds Django settings, Flask apps, Node servers, config files, and .env variants.
- Non-destructive auto-patching with backups and safety tags to prevent duplicate edits.
- Export and selective cleanup of issued certs

![cert_fronted](https://github.com/user-attachments/assets/cf2c35b0-8875-4b3b-8ec5-2d5301d31406)

![certcert](https://github.com/user-attachments/assets/07d0437d-1686-41ab-98c6-abb3f28a56e8)

# Installation

      pip install cryptography
      git clone https://github.com/Alb4don/CertCen.git
      cd certcen
      python certcen.py

- Choose 1 to set up the Root CA.
  
- Provide a common name ***(default: “CertCen Development Root CA”), organization, and two-letter country code.***
  
- The script generates the key and certificate, then offers to install it into the system trust store. Accept if you want browsers and tools to trust it immediately.

- Choose 2 to generate a domain certificate.

- Enter the primary hostname ***(e.g., localhost or myapp.local).***

- Add extra SANs (comma-separated). The tool suggests sensible defaults including loopback addresses.

- Confirm, and it creates a dedicated subdirectory ***under ~/.certcen/issued/ containing yourdomain.crt and yourdomain.key.***

- (Optional) When prompted, let it scan the current directory and patch detected dev-server files.

# Limitations

- No revocation lists or OCSP.
  
- No support for ECDSA or other key types yet (RSA 4096 only).
  
- Auto-detection is heuristic and may miss complex or heavily customized setups.
  
- Trust installation may require manual steps on certain Linux distributions or locked-down environments.

- The tool assumes you run it interactively; no non-interactive CLI flags exist.
