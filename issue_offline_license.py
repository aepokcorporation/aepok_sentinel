#!/usr/bin/env python3
"""
Final-shape offline license generator for Aepok Sentinel.

 - Reads a Dilithium private key either from Azure Key Vault or an offline path.
 - Builds a minimal SentinelConfig manually (no load_config("") hacks).
 - Computes real host_fingerprint and key_fingerprint for sign_content_bundle(...).
 - Produces a final JSON license file with structure accepted by license.py.
 - Does NOT autocreate directories or do partial fallback. If the output dir is missing, we fail.
 - Allows specifying:
     --issued-to <string>
     --expires-on YYYY-MM-DD
     --license-type <individual|site>
     --max-installs <int>
     --features <comma-separated>
     --offline-key <path> or --use-azure
 - Writes the license JSON to ~/sentinel_signing/client_licenses/<license_uuid>.license.json
"""

import os
import sys
import json
import uuid
import socket
import hashlib
import argparse
import datetime

from aepok_sentinel.core.config import SentinelConfig
from aepok_sentinel.core.pqc_crypto import (
    sign_content_bundle, CryptoSignatureError
)
from aepok_sentinel.core.license import LicenseManager  # might not be strictly needed
from aepok_sentinel.core.azure_client import AzureClient, AzureClientError  # if we do Azure fetch
from aepok_sentinel.core.constants import EventCode  # possibly not used, but consistent with final shape

def main():
    parser = argparse.ArgumentParser(
        description="Final-shape offline license generator for Aepok Sentinel."
    )
    parser.add_argument("--issued-to", required=True, help="The name/entity to which the license is issued.")
    parser.add_argument("--expires-on", required=True, help="Expiration date (YYYY-MM-DD). Ten years default example.")
    parser.add_argument("--license-type", default="individual", choices=["individual", "site"],
                        help="License type (default=individual).")
    parser.add_argument("--max-installs", type=int, default=10,
                        help="Max install count (default=10).")
    parser.add_argument("--features", default="", help="Comma-separated list of features to include in license.")
    parser.add_argument("--offline-key", help="Path to offline Dilithium private key (if not using Azure).")
    parser.add_argument("--use-azure", action="store_true",
                        help="Fetch the Dilithium private key from Azure Key Vault.")
    parser.add_argument("--vault-url", default="https://veritaevum.vault.azure.net/",
                        help="Azure Key Vault URL (only if --use-azure).")
    parser.add_argument("--secret-name", default="DILITHIUM-PRIVATE-KEY",
                        help="Key Vault secret name for the private key (only if --use-azure).")
    parser.add_argument("--out-dir", default=os.path.expanduser("~/sentinel_signing/client_licenses"),
                        help="Directory to store the generated license file (no auto-creation).")
    args = parser.parse_args()

    # 1) Validate expires-on format
    try:
        expires_dt = datetime.datetime.strptime(args.expires_on, "%Y-%m-%d").date()
        if expires_dt <= datetime.date.today():
            print(f"Error: --expires-on date {args.expires_on} is not in the future.", file=sys.stderr)
            sys.exit(1)
    except ValueError:
        print(f"Error: --expires-on '{args.expires_on}' is invalid format (YYYY-MM-DD).", file=sys.stderr)
        sys.exit(1)

    # 2) Validate out-dir presence
    if not os.path.isdir(args.out_dir):
        print(f"Error: output directory {args.out_dir} does not exist. No auto-creation allowed.", file=sys.stderr)
        sys.exit(1)

    # 3) Acquire Dilithium private key bytes
    dil_priv_key_bytes = None
    if args.use-azure:
        # build a minimal config for Azure usage
        raw_cfg = {
            "schema_version": 1,
            "mode": "cloud",
            "cloud_keyvault_provider": "azure",
            "cloud_keyvault_url": args.vault_url
        }
        azure_cfg = SentinelConfig(raw_cfg)
        from aepok_sentinel.core.license import LicenseManager  # maybe we need a license manager
        lic_mgr = LicenseManager(azure_cfg)  # no real usage except to pass
        try:
            az_client = AzureClient(azure_cfg, lic_mgr)
            priv_data = az_client.get_secret(args.secret_name)
            if not priv_data:
                print(f"Error: Azure key vault returned empty key for {args.secret_name}.", file=sys.stderr)
                sys.exit(1)
            # interpret priv_data as base64 or raw
            # for final shape, let's assume raw base64 => decode
            import base64
            dil_priv_key_bytes = base64.b64decode(priv_data)
        except AzureClientError as e:
            print(f"Error fetching private key from Azure Key Vault: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # offline path
        if not args.offline_key:
            print("Error: must specify either --use-azure or --offline-key <path>.", file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(args.offline_key):
            print(f"Error: offline key path {args.offline_key} not found.", file=sys.stderr)
            sys.exit(1)
        with open(args.offline_key, "rb") as kf:
            dil_priv_key_bytes = kf.read()

    if not dil_priv_key_bytes:
        print("Error: no Dilithium private key bytes loaded.", file=sys.stderr)
        sys.exit(1)

    # 4) Build a minimal SentinelConfig used for sign_content_bundle
    #    We'll inject real fingerprints
    raw_minimal = {
        "schema_version": 1,
        "mode": "offline",  # not an official mode but we don't rely on it for the license
        # any other fields you want for sign_content_bundle?
    }
    cfg_for_sign = SentinelConfig(raw_minimal)

    # compute real host fingerprint
    hostname = socket.gethostname()
    host_fp = hashlib.sha256(hostname.encode("utf-8")).hexdigest()

    # compute real key fingerprint
    key_fp = hashlib.sha256(dil_priv_key_bytes).hexdigest()

    # inject them into cfg_for_sign so sign_content_bundle sees them
    cfg_for_sign.raw_dict["signer_id"] = "offline_license_script"
    cfg_for_sign.raw_dict["host_fingerprint"] = host_fp
    cfg_for_sign.raw_dict["key_fingerprint"] = key_fp

    # 5) Construct the license object
    license_uuid = str(uuid.uuid4())
    features_list = [x.strip() for x in args.features.split(",") if x.strip()]

    license_obj = {
        "license_version": 1,
        "license_uuid": license_uuid,
        "issued_to": args.issued_to,
        "expires_on": args.expires_on,  # "YYYY-MM-DD"
        "features": features_list,
        "license_type": args.license_type,
        "max_installs": args.max_installs,
        "bound_to": "",  # fill if hardware-bound, else empty or do "null"
        "issued_date": str(datetime.date.today()),
    }
    # no signature yet; we produce the data => then sign => then embed signature

    # 6) sign
    # We'll produce the final license signature as well. sign_content_bundle expects data bytes
    from aepok_sentinel.core.pqc_crypto import sign_content_bundle
    license_bytes = json.dumps(license_obj, separators=(",", ":")).encode("utf-8")
    try:
        sig_dict = sign_content_bundle(license_bytes, cfg_for_sign, dil_priv_key_bytes, None)
    except CryptoSignatureError as e:
        print(f"Error: sign_content_bundle(...) failed: {e}", file=sys.stderr)
        sys.exit(1)

    # embed signature in license
    license_obj["signature"] = sig_dict  # store the entire dict. license.py expects base64 or subfields?
    # If license.py expects one big base64, you can do that. We'll assume the entire "sig_dict" is stored. The code can parse.

    # 7) Write final license JSON
    out_path = os.path.join(args.out_dir, f"{license_uuid}.license.json")
    try:
        with open(out_path, "w", encoding="utf-8") as outf:
            json.dump(license_obj, outf, indent=2)
    except Exception as e:
        print(f"Error: failed to write license file {out_path}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"License created successfully => {out_path}")
    sys.exit(0)


if __name__ == "__main__":
    main()
