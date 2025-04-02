# Aepok Sentinel
**Cryptographically Enforced File Protection for Regulated and Hostile Environments**

Built for SCIF, airgap, regulated enterprise, and forensic-grade deployments.

## Overview
Aepok Sentinel is a cross-platform, zero-trust file protection system that provides:

- **Hybrid post-quantum encryption** using AES-256-GCM, Kyber, and RSA

- **Tamper-evident audit chains** with full cryptographic linkage and Merkle validation

- **Runtime enforcement modes:** `scif`, `airgap`, `cloud`, `demo`, `watch-only`

- **License enforcement & hardware binding**

- **Real-time file scanning & auto-quarantine daemon**

- **Full CLI and GUI parity for all security actions**

- **12-step enforced build sequence** with zero soft assumptions or placeholder logic

- **Certifiability mapped to NIST 800-53, ISO 27001, DISA STIGs, and more**

This project is developed under a “final shape” doctrine: every module is immutable once built, all compatibility is proven, not promised, and the system is legally defined by this specification.

## Quickstart
**For normal systems with internet access:**
```bash
pip install aepok-sentinel
```
**For SCIF or airgap systems, place locally built wheels in a `./wheels` directory:**
```bash
pip install --no-index --find-links ./wheels aepok-sentinel
```

Then:

**Activate the system with a valid license**
```bash
sentinel --activate
```
and
### Verify the system is operational
```bash
sentinel --status
```

## Security Best Practices for Installation
To ensure the highest level of security during installation, follow these hardening steps:

### 1. Use a VeraCrypt Drive
- Create a dedicated VeraCrypt volume to store Sentinel installation files.

- This provides encrypted-at-rest storage for `.whl` files, license keys, and config.

Learn how to create a VeraCrypt volume: https://veracrypt.eu/en/Beginner%27s%20Tutorial.html

### 2. Perform a Virus Scan
- Scan all installation files with a reputable, up-to-date antivirus solution prior to use.

- This includes `.whl` files, `license.key`, and `.sentinelrc`.

**Disclaimer:** Sentinel itself is cryptographically self-validating, but these extra precautions guard against host-level compromise during initial deployment.

## .sentinelrc Configuration
Sentinel uses a strict JSON config file to control runtime behavior.

Example (`~/.sentinelrc`):
```json
{
  "schema_version": 1,
  "mode": "scif",
  "encrypt_extensions": [".docx", ".pdf"],
  "rotation_interval_days": 30,
  "log_path": "/var/log/sentinel/",
  "license_path": "/etc/sentinel/license.key",
  "scan_paths": ["/classified/files"],
  "scan_recursive": true,
  "quarantine_enabled": true,
  "decryption_requires_chain": true,
  "bound_to_hardware": true,
  "license_required": true
}
```

## Runtime Modes
| Feature         | SCIF/SCADA     | AIRGAP       | CLOUD         | WATCH-ONLY   | DEMO          |
|----------------|----------------|--------------|---------------|--------------|---------------|
| Network Access | None           | None         | Full (TLS1.3) | None         | Optional      |
| Encryption     | Yes            | Yes          | Yes           | No           | Mock or real  |
| Key Source     | Local only     | Local only   | Azure Vault   | Read-only    | Local/mock    |
| Audit Chain    | Full, signed   | Full, signed | Full, signed  | Read-only    | Signed or mock|
| Console Output | Disabled       | Minimal      | Enabled       | Enabled      | Enabled       |


## CLI Usage
```bash
sentinel --activate                 # Activate using license file
sentinel --status                  # Print daemon/license/audit status
sentinel --decrypt <file>          # Decrypt a file (if audit chain is intact)
sentinel --verify-chain            # Validate audit chain integrity
sentinel --debug-console           # Enable console logs in SCIF (if override allowed)
```

## GUI
Launch with:

```bash
sentinel-gui
```
- Fully mode-aware interface (features greyed-out in watch-only or SCIF)

- Real-time daemon status, logs, threat viewer

- License prompt and secure decryption tools

## Audit Chain Integrity
Every critical event is written to an append-only, hash-linked, signed chain:

```json
{
  "timestamp": "2025-04-01T18:42:19Z",
  "event": "file_encrypted",
  "metadata": { "path": "/classified/secret.docx" },
  "prev_hash": "...",
  "entry_hash": "...",
  "signature": "..."
}
```
If the chain is broken or tampered:

- **All encryption and decryption operations are halted**

- The daemon logs `CHAIN_BROKEN` and enters safe mode

- Requires manual `--verify-chain` and admin intervention

## Cryptographic Format
All encrypted files follow this payload structure:

```json
{
  "version": 1,
  "ciphertext": "...",
  "wrapped_key_kyber": "...",
  "wrapped_key_rsa": "...",
  "iv": "...",
  "integrity": "sha512",
  "signatures": {
    "dilithium": "...",
    "rsa": "..."
  }
}
```
|
**AES-256-GCM is default. CBC+HMAC supported if explicitly configured.**

## SCIF / Airgap Deployment Bundles

For isolated systems, use `deploy/scif_bundle/` or `deploy/airgap_bundle/`:

- All `.whl` and dependency files pre-packaged with SHA256 integrity checks

- `install_env.sh` to block internet pip access

- `verify_install.py` for post-install audit

- Pre-signed `.sentinelrc` templates
|
**No network calls. No live package fetches. Fully reproducible from disk.**

## Offline Installation Package (SCIF / Airgap)

For SCIF and fully airgapped environments, Sentinel ships as a sealed offline bundle located at:

```bash
deploy/scif_bundle/      # SCIF-locked environment
deploy/airgap_bundle/    # Standard airgapped system
```

These bundles include:

- **All** `.whl` **and dependency files**
  - SHA256-verified
  - Built against pinned versions for your environment
  - No network fetches permitted during install

- `install_env.sh`
  - Blocks pip from reaching the internet
  - Verifies integrity before install
  - Runs in hardened mode (safe for classified disks)

- `verify_install.py`
  - Ensures all modules are working post-install
  - Confirms:
    - Correct cryptographic libraries
    - License and hardware fingerprint match
    - `.sentinelrc` passes schema + policy checks
    - PQC availability confirmed
    - Audit chain can be initialized

- **Signed configuration templates:**
  - `.sentinelrc` (mode=`scif`)
  - `.sentinelrc` (mode=`airgap`)
  - Include enforced flags for console suppression, audit chaining, no override

- **Hash manifest:**
  - `SHA256SUMS.txt`
  - Optional `.sig` GPG or `Dilithium` signature file
  - Chain-compatible for audit record initialization

---

**To install Sentinel in a secure offline deployment:**

```bash
# Step 1: Mount sealed USB or drive containing the offline bundle
cd /mnt/usb/deploy/scif_bundle/

# Step 2: Run installation script
chmod +x install_env.sh
./install_env.sh

# Step 3: Run post-install validation
python3 verify_install.py
```

If any step fails, installation is aborted and must be manually investigated.

This process guarantees full compliance with:
- **NIST 800-53 SC-13 / SC-12**

- **NSA CSfC offline deployment rules**

- **ISO 27001 A.12.6 and A.14.2**

- **Zero Trust offline asset handling**

---

**Important:**
No Sentinel installation is valid until `verify_install.py` completes successfully and logs are written to the audit chain. All deployments in `scif` or `airgap` mode are considered **sealed systems**—updates must go through the **Patch Lifecycle** and be cryptographically validated before execution.

## Certifiability & Compliance

Sentinel maps to:

- **NIST 800-53 Rev5:** AU-2, AU-9, SC-12, SC-13, SI-7, CM-14

- **ISO 27001 (Annex A):** A.8.2, A.12.4, A.14.2

- **DISA STIG:** Logging, crypto enforcement, service hardening

- **CSfC:** Suitable as a software layer in dual-encryption architecture

A full certification mapping is included in:
`deploy/certification/control_map.xlsx`

## Compatibility Matrix

| OS                   | Arch   | Status           | GUI     | PQC Support     |
|----------------------|--------|------------------|---------|-----------------|
| Ubuntu 24.04         | x86_64 | Supported        | Yes     | Full (liboqs)   |
| RHEL 9               | x86_64 | Supported        | Yes     | Full (liboqs)   |
| Windows Server 2022  | x64    | Partially Supp   | Partial | Full (liboqs)   |
| macOS 14             | ARM64  | Unsupported      | No      | No liboqs       |
|
**“Supported” = full tests pass on real PQC with pinned crypto versions.**

## Development Standards

- **Strict PEP8**, enforced with `flake8` and `black`

- **12-step final-shape pipeline**

- **No placeholder code**, no dynamic imports

- **Every build step gated by full OS × Mode test matrix**

CI pipeline lives at: `.github/workflows/sentinel_ci.yaml`

## Legal & Licensing

Sentinel uses signed license files:

- `individual` (hardware-bound via SHA256(MAC+host+salt))

- `site` (portable, unrestricted host usage)

If license is:

- **Missing or expired:** System enters watch-only

- **Bound mismatch:** Watch-only or fail, per policy

- **Tampered:** Rejected; must re-authenticate

## Patch Lifecycle

You **cannot retroactively edit modules.** To issue a patch:

1. Increment `schema_version` in `.sentinelrc`

2. Bump module version

3. Re-run all module + integration tests

4. Log patch event in audit chain

## Contribution

This repository operates under a zero-guessing policy. PRs are only accepted if:

- All associated test cases pass

- No undefined logic or TODOs exist

- Dependencies are pinned

## Contact

**Aepok Corporation**

www.aepokcorp.com

Sentinel Inquiries: sentinel@aepokcorp.com

## License

Proprietary. All rights reserved. Licensed deployments must be authorized by Aepok Corporation. Redistribution or tampering is prohibited. Violators are subject to license degradation and cryptographic revocation.

