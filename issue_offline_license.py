#!/usr/bin/env python3
# issue_offline_license.py
"""
Offline License Generator for Aepok Sentinel

Produces a single `.key` file containing:
 - A base64-wrapped JSON blob with core license fields (license_uuid, expires_on, etc.)
 - A cryptographic signature using a Dilithium private key (from Azure or an offline file).
 - Enforces maximum duration of 10 years from the current date.
 - Fails if output directory doesn't exist; no automatic creation is performed.

Usage example:
  python3 issue_offline_license.py \
    --issued-to "SomeClient" \
    --expires-on "2035-01-01" \
    --license-type "individual" \
    --max-installs 5 \
    --features "enc,airgap" \
    --offline-key /path/to/dilithium_priv.bin \
    --out-dir /home/user/sentinel_signing/client_licenses
"""

import os
import sys
import json
import uuid
import socket
import hashlib
import argparse
import datetime
import base64

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.pqc_crypto import sign_content_bundle, CryptoSignatureError
from aepok_sentinel.core.azure_client import AzureClient, AzureClientError


def main():
    parser = argparse.ArgumentParser(
        description="Offline license generator for Aepok Sentinel (final shape)."
    )
    parser.add_argument("--issued-to", required=True, help="Name/entity to which the license is issued.")
    parser.add_argument("--expires-on", required=True, help="Expiration date (YYYY-MM-DD). Must be <= 10 years from today.")
    parser.add_argument("--license-type", default="individual", choices=["individual", "site"],
                        help="License type. Defaults to 'individual'.")
    parser.add_argument("--max-installs", type=int, default=10,
                        help="Maximum number of distinct installations allowed. Default=10.")
    parser.add_argument("--features", default="",
                        help="Comma-separated list of feature flags in this license.")
    parser.add_argument("--offline-key", help="Path to an offline Dilithium private key (if not using Azure).")
    parser.add_argument("--use-azure", action="store_true",
                        help="Fetch the Dilithium private key from Azure Key Vault instead of a local file.")
    parser.add_argument("--vault-url", default="https://veritaevum.vault.azure.net/",
                        help="Azure Key Vault URL (relevant only with --use-azure).")
    parser.add_argument("--secret-name", default="DILITHIUM-PRIVATE-KEY",
                        help="Key Vault secret name for the private key (only if --use-azure).")
    parser.add_argument("--out-dir", default=os.path.expanduser("~/sentinel_signing/client_licenses"),
                        help="Directory where the generated .key file is placed (must already exist).")
    args = parser.parse_args()

    # Validate 'expires-on' format and enforce a maximum of 10 years from today.
    try:
        expires_dt = datetime.datetime.strptime(args.expires_on, "%Y-%m-%d").date()
    except ValueError:
        print(f"Error: invalid --expires-on format '{args.expires_on}' (use YYYY-MM-DD).", file=sys.stderr)
        sys.exit(1)

    today = datetime.date.today()
    if expires_dt <= today:
        print(f"Error: expires-on date {args.expires_on} is not in the future.", file=sys.stderr)
        sys.exit(1)

    # Enforce a maximum license duration of 10 years from today.
    ten_years_later = today + datetime.timedelta(days=3650)
    if expires_dt > ten_years_later:
        print(f"Error: expiration date {args.expires_on} exceeds the 10-year maximum limit.", file=sys.stderr)
        sys.exit(1)

    # Check the output directory's existence (no auto-creation).
    if not os.path.isdir(args.out_dir):
        print(f"Error: output directory '{args.out_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # Acquire Dilithium private key bytes
    dil_priv_key_bytes = None
    if args.use_azure:
        # Minimal config for Azure usage
        raw_cfg = {
            "schema_version": 1,
            "mode": "cloud",
            "cloud_keyvault_provider": "azure",
            "cloud_keyvault_url": args.vault_url
        }
        azure_cfg = SentinelConfig(raw_cfg)
        from aepok_sentinel.core.license import LicenseManager  # Not strictly required but consistent
        lic_mgr = LicenseManager(azure_cfg)
        try:
            az_client = AzureClient(azure_cfg, lic_mgr)
            priv_data = az_client.get_secret(args.secret_name)
            if not priv_data:
                print(f"Error: Key Vault returned empty secret for '{args.secret_name}'.", file=sys.stderr)
                sys.exit(1)
            # Assume priv_data is base64
            dil_priv_key_bytes = base64.b64decode(priv_data)
        except AzureClientError as e:
            print(f"Error fetching private key from Azure: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Offline path usage
        if not args.offline_key:
            print("Error: must specify --use-azure or --offline-key <path>.", file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(args.offline_key):
            print(f"Error: offline key file '{args.offline_key}' not found.", file=sys.stderr)
            sys.exit(1)
        with open(args.offline_key, "rb") as kf:
            dil_priv_key_bytes = kf.read()

    if not dil_priv_key_bytes:
        print("Error: no Dilithium private key bytes loaded.", file=sys.stderr)
        sys.exit(1)

    # Prepare minimal config for signing
    raw_minimal = {
        "schema_version": 1,
        "mode": "offline"
    }
    from aepok_sentinel.core.config import SentinelConfig
    cfg_for_sign = SentinelConfig(raw_minimal)

    # Build some host/key fingerprints
    hostname = socket.gethostname()
    host_fp = hashlib.sha256(hostname.encode("utf-8")).hexdigest()
    key_fp = hashlib.sha256(dil_priv_key_bytes).hexdigest()

    cfg_for_sign.raw_dict["signer_id"] = "offline_license_script"
    cfg_for_sign.raw_dict["host_fingerprint"] = host_fp
    cfg_for_sign.raw_dict["key_fingerprint"] = key_fp

    # Construct the license object
    license_uuid = str(uuid.uuid4())
    features_list = [f.strip() for f in args.features.split(",") if f.strip()]

    license_obj = {
        "license_version": 1,
        "license_uuid": license_uuid,
        "issued_to": args.issued_to,
        "expires_on": args.expires_on,
        "features": features_list,
        "license_type": args.license_type,
        "max_installs": args.max_installs,
        "bound_to": "",
        "issued_date": str(today)
    }

    # Sign the license object
    from aepok_sentinel.core.pqc_crypto import sign_content_bundle, CryptoSignatureError
    license_bytes = json.dumps(license_obj, separators=(",", ":")).encode("utf-8")
    try:
        sig_dict = sign_content_bundle(license_bytes, cfg_for_sign, dil_priv_key_bytes, None)
    except CryptoSignatureError as e:
        print(f"Error signing the license: {e}", file=sys.stderr)
        sys.exit(1)

    license_obj["signature"] = sig_dict
    final_json = json.dumps(license_obj, separators=(",", ":"))
    final_b64 = base64.b64encode(final_json.encode("utf-8")).decode("utf-8")

    # Write .key file
    out_filename = f"{license_uuid}.key"
    out_path = os.path.join(args.out_dir, out_filename)
    
    try:
        with open(out_path, "w", encoding="utf-8") as outf:
            outf.write(final_b64)
    except Exception as e:
        print(f"Error writing license file {out_path}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"License created successfully => {out_path}")
    sys.exit(0)


if __name__ == "__main__":
    main()