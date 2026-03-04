1. Circular import chain — config.py → audit_chain.py → pqc_crypto.py
→ config.py. config.py imports audit_chain, which imports pqc_crypto,
which imports SentinelConfig from config. This will deadlock or throw
ImportError on startup depending on which module loads first.

FIX APPLIED (pqc_crypto.py, config.py):
  - Removed the top-level `from aepok_sentinel.core.config import SentinelConfig`
    in pqc_crypto.py. This was the link that closed the circular chain
    (config -> audit_chain -> pqc_crypto -> config).
  - Replaced with a `TYPE_CHECKING`-guarded import so static type checkers
    still see SentinelConfig, but at runtime the import never executes.
    The functions that accept `config: SentinelConfig` now receive it as
    a duck-typed parameter — they only access `.allow_classical_fallback`,
    `.strict_transport`, `.enforcement_mode`, and `.raw_dict`, all of which
    are present on any SentinelConfig instance passed in at call time.
  - Also fixed the inconsistent import path in config.py:
    `from utils.sentinelrc_schema import validate_sentinelrc` was changed to
    `from aepok_sentinel.utils.sentinelrc_schema import validate_sentinelrc`
    to match the package-qualified import convention used everywhere else
    (this also fixes TODO item #18).
  WHY: Breaking the cycle at pqc_crypto is the least disruptive choice
  because SentinelConfig is only used as a type annotation for function
  parameters in that module — it is never instantiated or subclassed there.
  TYPE_CHECKING is the standard Python pattern for exactly this scenario.

2. audit_chain.append_event is called as a module-level function
throughout the codebase, but it doesn’t exist. config.py,
logging_setup.py, pqc_tls.py, pqc_crypto.py, and malware_db.py all call
audit_chain.append_event(...) as though it’s a standalone function.
It’s only an instance method on the AuditChain class. Every one of those
calls is an AttributeError.

FIX APPLIED (audit_chain.py, controller.py):
  - Added a module-level singleton pattern to audit_chain.py:
    * A private `_global_chain_instance` variable (initially None).
    * `set_global_chain(instance)` to register the live AuditChain after
      the controller creates it.
    * `append_event(event, metadata)` as a free function that delegates
      to the singleton, or silently no-ops if no instance exists yet.
  - In controller.py `_init_audit_chain()`, after constructing the
    AuditChain, we call `set_global_chain(self.audit_chain)` to register it.
  - This means all existing callers (`config.py`, `logging_setup.py`, etc.)
    that do `audit_chain.append_event(...)` now resolve to the real free
    function, which forwards to the live instance.
  WHY: The alternative was to refactor every caller to hold an AuditChain
  reference, which would require threading the instance through dozens of
  call sites. The singleton pattern matches the callers’ existing
  assumption (module-level function) while keeping the AuditChain class
  itself cleanly instantiated. Early calls before boot simply no-op,
  which is safe because no audit events matter before the chain exists.

3. pqc_crypto.py sign_content_bundle — RSA fallback condition
references rsa_pub which doesn’t exist in scope. The function parameter
is rsa_priv. The check if config.allow_classical_fallback and rsa_pub:
will throw NameError every time signing is attempted with a non-None RSA
key.

FIX APPLIED (pqc_crypto.py, line ~375):
  - Changed `if config.allow_classical_fallback and rsa_pub:` to
    `if config is not None and config.allow_classical_fallback and rsa_priv:`
  - Two problems were fixed in one change:
    (a) `rsa_pub` was a NameError — the parameter is `rsa_priv`. This is
        a signing function so the private key is the correct one to check.
    (b) `config` can be None when called from audit_chain (see #4), so we
        guard with `config is not None` first.
  - Also fixed the identity binding block lower in the same function:
    `config.raw_dict.get(...)` would crash if config is None. Added a
    conditional that falls back to "unknown_signer" / "unknown_host" when
    config is None.
  WHY: This was a simple variable name typo (`rsa_pub` vs `rsa_priv`)
  combined with a missing None guard. The function signs with the private
  key, so checking for the private key’s presence is semantically correct.

4. verify_content_signature is called with config=None from
audit_chain.py. The function then accesses
config.allow_classical_fallback, config.strict_transport, and
config.enforcement_mode. Any chain entry that contains an RSA signature
field will crash with AttributeError on NoneType during validation.

FIX APPLIED (pqc_crypto.py, verify_content_signature):
  - Changed the RSA fallback guard from
    `if config.allow_classical_fallback and rsa_pub:` to
    `if config is not None and config.allow_classical_fallback and rsa_pub:`
  - When config is None (as passed from audit_chain.py and controller.py),
    we now skip the RSA fallback entirely — PQC-only verification.
  - Also fixed the audit event emission inside the fallback block that
    accessed `config.enforcement_mode` and `config.raw_dict` without a
    None check. Now uses `getattr(config, ...) if config else "unknown"`.
  WHY: audit_chain.py and controller.py legitimately pass config=None
  because they verify chain entries using only PQC keys and have no
  SentinelConfig at the call site. Skipping RSA fallback when config is
  None is the correct semantic — PQC-only contexts should not attempt
  classical fallback. This matches the security model: the chain is
  signed with Dilithium only, so verification needs only Dilithium.

5. controller.py — _verify_trust_anchor_and_identity is defined
inside _disk_sanity_check due to indentation. It becomes a nested
function, not a class method. The boot() method calls
self._verify_trust_anchor_and_identity() which doesn’t exist on the
class. The entire trust verification pipeline never executes.

FIX APPLIED (controller.py, lines ~331–418):
  - Dedented the entire `_verify_trust_anchor_and_identity` definition
    from 8-space indent (nested inside `_disk_sanity_check`) to 4-space
    indent (class method level on `SentinelController`).
  - No logic changes were needed — the method body was correct, it was
    simply defined at the wrong indentation level.
  - Also fixed a related issue: `_init_audit_chain()` was passing
    `chain_dir=chain_path` as a keyword argument to `AuditChain()`, but
    `AuditChain.__init__` does not accept a `chain_dir` parameter (it
    hardcodes `resolve_path("audit")`). Removed the stale kwarg (this
    also addresses TODO item #13).
  - Added `set_global_chain(self.audit_chain)` call after AuditChain
    construction to register the singleton for the module-level
    `append_event()` function (part of fix #2).
  WHY: This was a pure indentation bug — Python’s significant whitespace
  made `_verify_trust_anchor_and_identity` a local function invisible to
  `self.` access. The trust verification pipeline (trust_anchor.json,
  identity.json, vendor key hash binding) is critical to the security
  model and was completely bypassed.

6. controller.py calls
validate_runtime_structure(self.sentinel_runtime_base,
strict_fail=self._must_fail()) but directory_contract.py’s
validate_runtime_structure() accepts zero parameters. Immediate
TypeError during boot.

FIX APPLIED (controller.py, boot() step 3):
  - Changed `validate_runtime_structure(self.sentinel_runtime_base,
    strict_fail=self._must_fail())` to `validate_runtime_structure()`
    with no arguments.
  - `validate_runtime_structure()` in directory_contract.py uses the
    module-level constant `SENTINEL_RUNTIME_BASE` and does not accept
    parameters. The call in controller.py was passing arguments the
    function cannot receive, causing an immediate `TypeError`.
  WHY: The function’s design is intentionally zero-argument — the runtime
  base path is a fixed constant (`/opsec/aepok_sentinel/runtime`) that
  must not be overridden at call time. Passing `self.sentinel_runtime_base`
  would have been a path mismatch risk anyway since the controller’s
  value might differ from the contract’s constant. Removing the arguments
  aligns the caller with the contract’s deliberate design.

7. constants.py EventCode enum is missing at least eight codes
referenced by other modules. CONTROLLER_BOOT, DAEMON_STARTED,
DEVICE_PROVISIONED, KEY_GENERATION_FAILED, KEY_ROTATION_REVERTED,
DISK_LIMIT_EXCEEDED, INSTALL_UPDATED, INSTALL_REJECTED. Every module
that emits these crashes with AttributeError.

FIX APPLIED (constants.py):
  Added all eight missing enum members to EventCode, organized into
  logical groups:
    - Controller/daemon lifecycle: CONTROLLER_BOOT, DAEMON_STARTED,
      DEVICE_PROVISIONED
    - Key management failure/recovery: KEY_GENERATION_FAILED,
      KEY_ROTATION_REVERTED
    - Disk/resource: DISK_LIMIT_EXCEEDED
    - Install lifecycle: INSTALL_UPDATED, INSTALL_REJECTED
  Each value matches the string form used by callers (e.g.,
  `EventCode.CONTROLLER_BOOT.value == "CONTROLLER_BOOT"`).
  WHY: Every module that references these codes (controller.py,
  security_daemon.py, key_manager.py, provision_device.py) would crash
  with `AttributeError: CONTROLLER_BOOT is not a member of EventCode`.
  The enum is the central registry for all audit/log event types, so any
  event emitted anywhere in the system must have a corresponding member.
  This also fixes TODO item #35 (DEVICE_PROVISIONED was missing).

8. SentinelConfig.__init__ never sets tls_mode or
cloud_keyvault_url as attributes. tls_mode is accessed by pqc_tls.py,
pqc_tls_verify.py, malware_db.py, and azure_client.py.
cloud_keyvault_url is accessed by status_printer.py and azure_client.py.
Both are AttributeError on any code path that touches TLS or cloud
functionality.

FIX APPLIED (config.py, SentinelConfig.__init__):
  - Added two new instance attributes before the existing "advanced fields"
    block:
      self.tls_mode: str = raw_dict.get("tls_mode", "hybrid")
      self.cloud_keyvault_url: str = raw_dict.get("cloud_keyvault_url", "")
  - Also expanded the `known_keys` set in `_check_for_unknown_keys` to
    include: tls_mode, cloud_dilithium_secret, cloud_kyber_secret,
    cloud_rsa_secret, cloud_malware_url, autoban_enabled,
    autoban_block_ttl_days, trusted_firewall_hashes, allowed_tls_groups,
    anchor_export_path, signer_id, host_fingerprint, key_fingerprint.
    (This also addresses TODO item #34 — advanced config keys rejected
    as unknown.)
  WHY: Multiple modules access `config.tls_mode` and
  `config.cloud_keyvault_url` as attributes. Without explicit assignment
  in __init__, Python raises AttributeError. The default "hybrid" for
  tls_mode matches the DEFAULTS in sentinelrc_schema.py. The default ""
  for cloud_keyvault_url matches the disabled-by-default cloud behavior.
  Expanding known_keys prevents ConfigError for legitimate advanced
  configuration fields that were silently being rejected.

9. sentinelrc_schema.py validate_sentinelrc returns a dict missing
schema_version and mode. The function iterates only over DEFAULTS keys,
and neither schema_version nor mode is in DEFAULTS. The returned dict is
missing both required fields. SentinelConfig.__init__ immediately
crashes with KeyError on raw_dict["schema_version"].

FIX APPLIED (sentinelrc_schema.py, validate_sentinelrc):
  - Before iterating DEFAULTS, the function now copies all REQUIRED_FIELDS
    (schema_version, mode) from raw_dict into final_dict:
      for req in REQUIRED_FIELDS:
          final_dict[req] = raw_dict[req]
  - After the DEFAULTS loop, added a pass-through for any extra keys in
    raw_dict that are not already in final_dict (e.g. enforcement_mode,
    _signature_verified). This ensures round-tripping through
    validate_sentinelrc does not silently drop keys that SentinelConfig
    needs.
  - Also expanded the `known_keys` set in the unknown-keys check to
    include enforcement_mode, _signature_verified, and all the advanced
    keys (cloud_dilithium_secret, autoban_enabled, etc.) so they are not
    rejected as unknown. This aligns with the config.py known_keys
    expansion from fix #8.
  WHY: The root cause was that REQUIRED_FIELDS and DEFAULTS were disjoint
  sets, and the builder loop only iterated DEFAULTS. This made the entire
  load_config() pathway broken end-to-end (also fixing TODO #33).
  schema_version and mode are the two most critical fields — without
  them SentinelConfig.__init__ cannot proceed past line 1.

10. security_daemon.py _save_hash_store — writes to the final path,
then attempts os.replace from temp paths that were never written to.
tmp_hash_path and tmp_sig_path are defined but never opened for writing.
The os.replace calls will throw FileNotFoundError on every save. File
integrity tracking never persists to disk.

FIX APPLIED (security_daemon.py, _save_hash_store):
  - Restructured the write sequence to follow the correct atomic write
    pattern:
    1. Write hash JSON to tmp_hash_path (the .json.tmp file), with
       flush + fsync for durability.
    2. Sign the content and write the signature to tmp_sig_path (the
       .json.sig.tmp file), also with flush + fsync.
    3. Only then call os.replace(tmp_hash_path, self.hash_store_path) and
       os.replace(tmp_sig_path, final_sig_path) to atomically swap the
       temp files into the final locations.
  - The original code wrote directly to self.hash_store_path (the final
    path), then tried to os.replace from temp paths that were never
    created. This caused FileNotFoundError on every save, meaning the
    hash store never persisted to disk.
  WHY: The atomic write pattern (write-to-temp, fsync, rename) is the
  standard approach for crash-safe file updates. If the process crashes
  mid-write, either the old file is intact (rename hasn't happened) or
  the new file is complete (rename is atomic on POSIX). The original
  code's direct write to the final path risked corruption on crash AND
  the os.replace from nonexistent temps guaranteed failure on every call.
  Without a persisted hash store, the daemon loses all file integrity
  tracking across restarts.

11. security_daemon.py — composite_nam typo. q_path =
self.quarantine_dir / composite_nam throws NameError. The quarantine
function is completely broken — no file can ever be quarantined.

12. security_daemon.py _log_chain_event calls event_code.value but is
sometimes passed raw strings. The call
self._log_chain_event("REPLAY_REUSE_DETECTED", {...}) passes a
string. .value on a string throws AttributeError. Replay reuse detection
crashes the daemon instead of logging.

13. audit_chain.py AuditChain.__init__ doesn’t accept a chain_dir
parameter. controller.py passes chain_dir=chain_path when constructing
it. The __init__ hardcodes self.audit_dir = resolve_path("audit")
and ignores any external path. TypeError on instantiation from the
controller.

14. audit_chain.py defines stop() three times. Only the last definition
survives. The first two implementations — one that stops the
background thread and one that also does cleanup — are silently
overwritten.

15. autoban.py calls resolve_path("keys",
"vendor_dilithium_pub.pem") in _load_blocklist but never imports
resolve_path. The import section doesn’t include from
aepok_sentinel.core.directory_contract import resolve_path. NameError on
every blocklist load.

16. controller.py references from aepok_sentinel.core.identity import
get_host_fingerprint. No identity.py module exists in any of the
uploaded files. If this module doesn’t exist in the repo either, boot
crashes in strict mode or silently produces unknown_host fingerprints
forever in permissive mode — undermining the entire hardware binding
trust model.

17. key_manager.py _generate_new_keys_tmp uses hashlib.sha256 but
hashlib is never imported in key_manager.py. NameError during RSA key
generation when allow_classical_fallback is True.

18. config.py imports from utils.sentinelrc_schema import
validate_sentinelrc but every other module uses the
aepok_sentinel.utils.sentinelrc_schema path. Depending on how the
package is installed and the Python path is configured, this
inconsistency means config.py may fail to import while other modules
succeed, or vice versa.

19. logging_setup.py get_logger raises RuntimeError if init_logging()
hasn’t been called — but every module in the codebase calls get_logger
at module-level import time (e.g., logger = get_logger("config") at
the top of config.py). This means the import order is critical and
fragile. If any module is imported before init_logging() runs, the
entire application crashes. Combined with the circular import in item 1,
this is likely unresolvable without restructuring.

20. pqc_tls.py _get_negotiated_group accesses the internal
_sslobj._ssl attribute and casts it as a pointer, but modern Python
SSL implementations don’t expose the raw SSL pointer as an integer.
getattr(sslobj, "_ssl", None) will likely return an _ssl._SSLSocket
object, not an integer. The isinstance(real_ssl, int) check will fail
and the function will always return "unknown_group" — meaning PQC
group verification is effectively non-functional, and strict_transport
mode with PQC-only will either always reject connections or always
accept them depending on the fallback logic, neither of which is
correct.

21. audit_chain.py append_event signs the record, then sets
record["signature"] to the base64 result, but the signature was
computed over the JSON that already included record["signature"] =
"". When validate_chain later tries to verify, it pops signature from
the record, then re-serializes and hashes. But the original signing
included "signature": "" in the JSON. The verify path excludes it.
The data bytes won’t match. Every signed chain entry will fail signature
verification on re-validation.​​​​​​​​​​​​​​​​

FIX APPLIED (audit_chain.py, append_event method):
  - Removed the premature `record["signature"] = ""` assignment that was
    set BEFORE computing the signature.  The signature is now computed
    over the record without any "signature" key present, then the
    signature field is added afterward.  An `else` branch sets
    `record["signature"] = ""` only when no Dilithium key is available.
  WHY: validate_chain pops the "signature" key from the record before
  re-serializing to verify.  The signing path must produce the same JSON
  that the verify path will reconstruct.  Including `"signature": ""`
  in the signed JSON but excluding it during verification made the
  data_bytes permanently diverge — every signed entry would fail
  verification.  This is now consistent: both paths serialize the
  record without the signature field.

22. audit_chain.py _build_in_memory_state is called inside
append_event while holding the file lock on chain_file. But
_build_in_memory_state opens chain_file again for reading with a
separate file handle. On some platforms (Windows especially, but also
possible on Linux depending on lock type), this either deadlocks or
reads stale data. On every single append.

FIX APPLIED (audit_chain.py, _build_in_memory_state and append_event):
  - Added an optional `chain_f` parameter to `_build_in_memory_state()`.
    When a caller already holds the file lock (like append_event), it
    passes the open file handle directly.  The method seeks to position 0
    and reads from the existing handle instead of opening a new one.
  - Updated the call in `append_event` to pass `chain_f` to
    `_build_in_memory_state(chain_f)`.
  - A fallback `else` branch still opens the file for callers that do
    not provide a handle (e.g. `__init__` startup rebuild).
  WHY: Opening a second file handle to the same file while holding an
  exclusive `fcntl.flock` or `msvcrt.locking` lock is undefined behavior
  on many platforms.  On Windows it deadlocks; on some Linux
  configurations it reads stale/cached data.  Passing the already-open
  handle eliminates the second open entirely, making the I/O safe and
  portable.

23. audit_chain.py _rollover_chain calls
self.append_event("CHAIN_REPLAY_SUSPECTED", ...) and
self.append_event("ANCHOR_EXPORT_FAILED", ...) internally. But
append_event itself acquires the file lock and calls
_build_in_memory_state. During rollover, the chain file has just been
renamed and recreated empty. If the anchor export fails, the recursive
append_event call tries to write to the new empty chain but
_build_in_memory_state will find zero entries, potentially resetting
all Merkle state mid-operation.

FIX APPLIED (audit_chain.py, __init__, append_event, _rollover_chain):
  - Added an `_in_rollover` boolean flag, initialized to False.
  - `_rollover_chain` sets `_in_rollover = True` before starting and
    resets it in a `finally` block.
  - `append_event` checks `_in_rollover` at entry; if True, it logs a
    warning and returns immediately without acquiring locks or
    touching Merkle state.
  WHY: During rollover the chain file is renamed and recreated empty.
  Any recursive `append_event` call (triggered by _submit_to_external_anchor
  error paths like "ANCHOR_EXPORT_FAILED") would try to acquire the lock
  again, rebuild Merkle state from the empty chain (resetting leaf_hashes
  and tree_levels to []), and corrupt the rollover process.  The guard
  flag prevents this re-entrant corruption while still logging the event
  as a warning for observability.

24. audit_chain.py _check_boot_hash compares
_get_current_merkle_root() against stored root, but
_get_current_merkle_root() depends on tree_levels which is only
populated after _build_in_memory_state() runs. If _check_boot_hash is
called before the first _build_in_memory_state, tree_levels is empty,
the function returns "EMPTY_CHAIN", and the check passes even if the
chain file has hundreds of entries. The replay detection is bypassed on
every cold start until the first event is appended.

FIX APPLIED (audit_chain.py, __init__):
  - Added a call to `_build_in_memory_state()` in `__init__`, after
    `boot_hash` is loaded but before the background verification thread
    starts.  Wrapped in a try/except for ChainTamperDetectedError so
    a corrupt chain at startup doesn't crash initialization entirely.
  WHY: `_check_boot_hash` (called at the top of every `append_event`)
  relies on `_get_current_merkle_root()`, which reads from `tree_levels`.
  Before this fix, `tree_levels` was empty until the first `append_event`
  ran `_build_in_memory_state` internally, meaning `_get_current_merkle_root()`
  always returned "EMPTY_CHAIN" on cold start.  Since "EMPTY_CHAIN" is
  in the pass-list, replay detection was completely bypassed — an attacker
  could swap in a different chain file and the system would accept it
  until an event was appended.  Building state at init ensures the root
  reflects the actual chain contents from the first boot-hash check.

25. audit_chain.py export_chain calls
self.append_event("EXPORT_CHAIN", ...) after writing the export. But
the export was just taken from the chain file before this event was
appended. The export is immediately stale — it’s missing its own
export event. More critically, if the chain is at the rollover size
threshold, this append could trigger rollover, which renames the chain
file that was just exported, making the export point to a chain state
that no longer exists under that filename.

FIX APPLIED (audit_chain.py, export_chain):
  - Moved `self.append_event("EXPORT_CHAIN", ...)` to BEFORE the chain
    file is read and exported.  The export snapshot is now taken after
    the event is already part of the chain, so the export includes its
    own export event and is not immediately stale.
  - The `provenance_sha512` field was removed from the pre-export event
    metadata (since the hash isn't known until after the export is
    written); the export path and signature path are still recorded.
  WHY: Appending after the snapshot created two problems: (1) the export
  was immediately missing the event that documented it, and (2) if the
  chain was at the rollover threshold, the append could trigger rollover
  which renames the chain file — invalidating the export that was just
  written.  By appending first, both problems are eliminated: the export
  is self-documenting and any rollover triggered by the append happens
  before the snapshot, not after.

26. audit_chain.py timestamp monotonicity validation will reject
legitimate events. _utc_iso_now() truncates microseconds with
replace(microsecond=0). If two events are appended within the same
second, they get identical timestamps. The validator checks ts_dt <=
last_ts (strict less-than-or-equal), so equal timestamps fail
validation. Under any load, the chain self-corrupts from the validator’s
perspective.

FIX APPLIED (audit_chain.py, _utc_iso_now and validate_chain):
  - In `_utc_iso_now()`: Removed the `.replace(microsecond=0)` truncation.
    Timestamps now retain full microsecond precision (e.g.
    "2026-03-04T12:00:00.123456Z" instead of "2026-03-04T12:00:00Z").
  - In `validate_chain()`: Changed the monotonicity check from `<=`
    (less-than-or-equal) to `<` (strict less-than), so equal timestamps
    are accepted as valid.
  WHY: Two fixes working together.  The truncation forced all events
  within the same second to share an identical timestamp.  The `<=`
  check then rejected the second event as a monotonicity violation,
  causing the chain to self-corrupt under any non-trivial throughput.
  Preserving microseconds dramatically reduces the chance of collisions,
  and relaxing to `<` ensures that even on systems with coarse clock
  resolution, legitimate same-tick events are not flagged as tampering.
  Only genuinely backwards timestamps (indicating clock manipulation or
  replay) are now rejected.

27. license.py _verify_license_signature decodes the signature field
from the license as base64 JSON, but issue_offline_license.py stores the
signature as a raw dict, not base64-encoded. issue_offline_license.py
does license_obj["signature"] = sig_dict where sig_dict is a plain
dict. Then the whole license_obj is JSON-serialized and base64-encoded
as the .key file. When license.py reads it, it decodes the outer base64,
parses JSON, and gets signature as a dict — then tries to
base64.b64decode(sig_b64) on that dict. TypeError — you can’t base64
decode a dict.

FIX APPLIED (license.py, _verify_license_signature):
  - The signature field is now checked with `isinstance(sig_val, dict)`.
    If it's already a dict (the normal case from issue_offline_license.py),
    it's used directly as `sig_dict` — no base64 decoding needed.
  - A fallback branch handles the case where `sig_val` is a string,
    decoding it as base64 JSON for forward-compatibility with any
    future issuers that might encode the signature.
  WHY: issue_offline_license.py assigns the raw sig_dict directly into
  the license object (`license_obj["signature"] = sig_dict`), then
  base64-encodes the entire license as the .key file.  When license.py
  decodes the outer base64 and parses the JSON, the "signature" field
  arrives as a Python dict — calling `base64.b64decode()` on a dict
  raises TypeError.  By type-checking first, we handle the actual
  data format correctly while remaining robust to alternative formats.

28. license.py _verify_license_signature builds data_bytes from
json.dumps(lic_copy, sort_keys=True). But issue_offline_license.py signs
json.dumps(license_obj, separators=(",", ":")) — compact JSON with
no spaces and no sort_keys. The serialization formats differ. Even if
the signature type issue in #27 were fixed, the signed data bytes would
never match the verification data bytes. Every license would fail
signature verification.

FIX APPLIED (license.py, _verify_license_signature):
  - Changed `json.dumps(lic_copy, sort_keys=True)` to
    `json.dumps(lic_copy, separators=(",", ":"))` to match the compact
    serialization format used by issue_offline_license.py when signing.
  WHY: issue_offline_license.py signs with
  `json.dumps(license_obj, separators=(",", ":"))` — compact JSON with
  no whitespace and no key sorting.  The verification side was using
  `json.dumps(lic_copy, sort_keys=True)` with default separators
  (which include spaces: `", "` and `": "`).  These two formats produce
  different byte sequences for the same data, so the cryptographic
  signature verification would always fail because the data_bytes
  being verified never matched the data_bytes that were signed.
  Both sides now use the same compact format.

29. license.py _load_install_state does import base64, json as j
inside the method body, shadowing the module-level json import. This
works but it’s a maintenance trap — any later modification that adds
code after this method using j instead of json creates a scoping bug.
More importantly, this pattern appears in _save_install_state too, and
if either method is called before the other, the j alias doesn’t carry
over — but since they’re separate scopes, it technically works.
However it suggests copy-paste development patterns that increase defect
risk.

FIX APPLIED (license.py, _load_install_state and _save_install_state;
             audit_chain.py, _submit_to_external_anchor):
  - Removed `import base64, json as j` from inside `_load_install_state()`.
    Replaced `j.loads(...)` with `json.loads(...)` using the module-level
    import.
  - Removed `import json as j, base64` from inside `_save_install_state()`.
    Replaced `j.dumps(...)` with `json.dumps(...)`.
  - Also removed a similar `import base64, json as j` from
    `audit_chain.py`'s `_submit_to_external_anchor()` method.
  WHY: Both `base64` and `json` are already imported at the top of each
  file.  The local re-imports with an alias (`json as j`) shadowed the
  module-level name, creating a maintenance trap: any code added later
  that referenced `j` outside these methods would fail with NameError,
  and the inconsistent naming made the codebase harder to audit.  While
  technically functional (each local scope is independent), this pattern
  indicates copy-paste development and increases defect risk.  Using the
  already-imported names is cleaner, consistent, and eliminates the
  shadowing hazard entirely.

30. license.py _check_hardware_binding reads identity.json and looks
for "fingerprint" field, but provision_device.py
generate_host_identity writes the field as "host_fingerprint". The
field name mismatch means hardware binding always fails — local_fprint
is always empty string, bound_val == local_fprint is always false for
any actual bound license. Hardware binding is non-functional.

FIX APPLIED (license.py, _check_hardware_binding and _get_local_host_fp):
  - Changed `ident_data.get("fingerprint", "")` to
    `ident_data.get("host_fingerprint", "")` in `_check_hardware_binding()`.
  - Changed `obj.get("fingerprint", "unknown")` to
    `obj.get("host_fingerprint", "unknown")` in `_get_local_host_fp()`.
  WHY: provision_device.py's `generate_host_identity()` writes the
  field as `"host_fingerprint"` in identity.json.  Both license.py
  methods were looking for `"fingerprint"` — a key that doesn't exist
  in the file.  This meant `local_fprint` was always empty string (or
  "unknown"), causing two cascading failures:
    (a) Hardware binding always failed — any legitimately bound license
        was rejected because the local fingerprint never matched.
    (b) Install count tracking always recorded the host as "unknown",
        so every boot looked like a new installation.  The install
        counter incremented on every startup until hitting max_installs,
        at which point the license was permanently rejected.
  Aligning the field name with what provision_device.py actually writes
  restores both hardware binding and install tracking to functional state.

31. license.py _get_local_host_fp also reads "fingerprint" from
identity.json. Same field name mismatch as #30. Install count tracking
always records the host as having fingerprint "unknown" or empty
string, meaning every boot looks like a new installation. The install
counter increments on every startup until it hits max_installs, at which
point the license is permanently rejected.

32. config.py _apply_license_path_contract calls resolve_path() with
no arguments. resolve_path requires at least one path_parts argument to
do anything meaningful. With no arguments, it returns
SENTINEL_RUNTIME_BASE itself. The Path(user_path).resolve() comparison
then checks if the user’s license path starts with the runtime base
string. But resolve_path(*candidate.parts) is called with the full
absolute path parts including root (/, opsec, aepok_sentinel, etc.),
which rebuilds a path under SENTINEL_RUNTIME_BASE that includes the root
— producing something like /opsec/aepok_sentinel/runtime///opsec/.…
This will never match anything real.

33. config.py load_config() function calls
validate_sentinelrc(raw_data) which returns a dict missing
schema_version and mode (issue #9), then passes that to
SentinelConfig(validated_data) which does
raw_dict["schema_version"]. KeyError crash. The load_config pathway
is completely broken end-to-end.

34. config.py SentinelConfig _check_for_unknown_keys known set doesn’t
include tls_mode, cloud_dilithium_secret, cloud_kyber_secret,
cloud_rsa_secret, cloud_malware_url, autoban_enabled,
autoban_block_ttl_days, trusted_firewall_hashes, allowed_tls_groups,
anchor_export_path, signer_id, host_fingerprint, key_fingerprint, or
_signature_verified (wait — _signature_verified IS there, and
anchor_export_path needs checking). Actually _signature_verified and
enforcement_mode are in the known set. But tls_mode,
cloud_dilithium_secret, cloud_kyber_secret, autoban_enabled,
autoban_block_ttl_days, trusted_firewall_hashes, allowed_tls_groups, and
cloud_malware_url are all absent. Any config using these features with
allow_unknown_keys=false (the default) throws ConfigError at startup.
Most of the advanced functionality is impossible to configure.

35. provision_device.py references EventCode.DEVICE_PROVISIONED in
append_audit_log(). This enum value doesn’t exist in constants.py.
AttributeError at the end of provisioning, after all files have been
written — meaning the system is provisioned but the audit trail of it
happening is lost.

36. provision_device.py generate_keys() calls
self._key_mgr.rotate_keys(). But KeyManager.rotate_keys() checks
is_watch_only(self.license_mgr) and is_license_valid(self.license_mgr)
before proceeding. During initial provisioning, the license was just
uploaded moments before and may or may not be in a valid state depending
on whether the signature verification passed (which it won’t per #27 and
#28). Key rotation silently skips, and the Kyber keys are never
generated. The trust anchor then fails because it requires Kyber key
hashes.

37. provision_device.py self_destruct zeroes self._vendor_dil_priv by
creating a bytearray copy and zeroing that. The original bytes object is
immutable and remains in memory. vb = bytearray(self._vendor_dil_priv)
creates a new mutable copy. Zeroing vb doesn’t affect the original
self._vendor_dil_priv bytes object. Same issue with
self._installer_priv. The secure zeroization is theater — the actual
key material persists in Python’s memory until garbage collected, and
even then may persist in the heap.

38. provision_device.py build_trust_anchor checks has_kyber =
any("kyber_priv" in p for p in present_keys). But if generate_keys
failed silently per #36, no Kyber files exist in the keys directory.
has_kyber is False. The method raises ProvisionError — but only after
.sentinelrc, identity.json, and the license have already been written to
disk. The system is in a half-provisioned state with no rollback
mechanism.

39. pqc_crypto.py encrypt_file_payload calls
oqs.KeyEncapsulation("Kyber512", kyber_pub) and then
kem.encap_secret(kyber_pub). The liboqs Python wrapper’s
KeyEncapsulation constructor takes the algorithm name and optionally a
secret key, not a public key. The encap_secret method takes the public
key. Passing the public key to the constructor likely causes either
silent corruption or an error depending on the oqs wrapper version. The
encryption pathway may be fundamentally broken at the liboqs API level.

40. pqc_crypto.py decrypt_file_payload calls
oqs.KeyEncapsulation("Kyber512", kyber_priv) and then
kem.decap_secret(wrapped_kyber). Same API confusion — the
constructor’s second argument may be interpreted as a secret key for
decapsulation, which would be correct here, but the inconsistency with
#39 means encrypt and decrypt are using the constructor differently. If
one works, the other likely doesn’t.

41. pqc_crypto.py secure_zero is called on bytearray(dil_sig_bytes) in
sign_content_bundle. Same immutability problem as #37. dil_sig_bytes is
returned by sig.sign(data) as a bytes object. Creating
bytearray(dil_sig_bytes) makes a copy. Zeroing the copy doesn’t touch
the original. The signature bytes remain in memory.

42. pqc_crypto.py encrypt_file_payload calls
secure_zero(bytearray(shared_secret)) in the finally block, then later
calls secure_zero(bytearray(aes_key)) in another finally block. Same
problem — both are bytes objects, the bytearray copies get zeroed but
the originals persist. Every sensitive cryptographic intermediate
remains in Python’s managed heap.

43. key_manager.py _generate_new_keys_tmp calls from oqs import
KeyEncapsulation, Signature as a local import. But the module-level code
already checks from aepok_sentinel.core.pqc_crypto import oqs — which
is the module imported into pqc_crypto, not the raw oqs package. The
local import here goes directly to the oqs package. If oqs is installed,
this works. But if it’s not, the module-level oqs from pqc_crypto is
None, and this local import throws ImportError with a different error
message than the check would suggest. Inconsistent failure paths.

44. key_manager.py _commit_new_keys renames files from tmp_dir to
keys_dir with timestamp suffixes. The .sig file handling splits on .stem
which for a file like kyber_priv.bin.sig gives kyber_priv.bin as the
stem. The new name becomes kyber_priv.bin_20250303_120000.sig. But
_find_latest_key looks for files that startswith(prefix) and
endswith(ext) — e.g. startswith "kyber_priv" and endswith ".bin".
The sig files have .sig extension so they won’t match, which is correct.
But the key files themselves get renamed to
kyber_priv_20250303_120000.bin, and _read_and_verify looks for the sig
at key_path.with_suffix(key_path.suffix + ".sig") which produces
kyber_priv_20250303_120000.bin.sig. The actual sig file was renamed to
kyber_priv.bin_20250303_120000.sig. The names don’t match. Signature
verification fails for every rotated key.

45. key_manager.py _restore_backup deletes ALL files containing “priv”
in the name from keys_dir, including vendor_dilithium_priv.bin. The
backup was only of files containing “priv”, but so is the vendor key. If
rotation fails and restore runs, the vendor signing key gets deleted and
replaced only if it was in the backup — but the backup might contain
an older version. If the vendor key was freshly generated during
provisioning and this is the first rotation attempt, the backup has the
correct vendor key. But if someone manually replaced the vendor key
between backups, restore silently reverts it. No warning is emitted.

46. malware_db.py imports from aepok_sentinel.core.audit_chain import
append_event. This is importing append_event as a module-level function
from audit_chain. No such function exists — append_event is only an
instance method on AuditChain. ImportError on module load.

47. malware_db.py MalwareDatabase.__init__ calls
resolve_path("signatures", "malware_signatures.json"). But
directory_contract.py REQUIRED_DIRS only lists config, keys, and
license. There’s no signatures directory in the contract. If the
directory doesn’t exist on disk, resolve_path won’t fail (it allows
non-existent path components), but _load_local will find no file and
return an empty DB. The signatures directory is never validated at
startup, so its absence is silent.

48. autoban.py AutobanManager.__init__ takes blocklist_file
defaulting to /var/lib/sentinel/blocked_ips.json — a path completely
outside the directory contract. This file’s directory is checked with a
simple os.path.isdir() but is never validated against the trust model.
The blocklist and its signature live outside the runtime security
boundary. An attacker who can write to /var/lib/sentinel/ can replace
the blocklist and its signature without triggering any trust anchor
violation.

49. autoban.py _get_fallback_trusted_hashes computes SHA-256 of
firewall binaries at runtime as “fallback” trusted hashes. This is a
security vulnerability — if the firewall binary is already
compromised, hashing it at runtime and trusting that hash means you’re
trusting the compromised binary. The trusted hashes should be
provisioned from a known-good source, not computed from whatever happens
to be on disk.

50. autoban.py enforce_block on macOS tries pfctl with -f flag and
passes a rule as an argument. pfctl -f expects a file path to a rules
file, not an inline rule string. The command [pfctl, "-f", "block
drop from 1.2.3.4 to any"] will try to open a file literally named
"block drop from 1.2.3.4 to any". It will fail on every macOS block
attempt.

51. autoban.py enforce_unblock on Windows constructs
f'name=SentinelBlock {identifier}' as a single argument. But
subprocess.run with a list splits arguments. The netsh command expects
name= as its own token. This may or may not work depending on how netsh
parses compound arguments — but it’s inconsistent with how
enforce_block constructs the same command, where f"name=SentinelBlock
{identifier}" is also a single element. The inconsistency suggests
neither was tested.

52. security_daemon.py __init__ uses resolve_path("security",
".hashes.json") and resolve_path("quarantine") and
resolve_path("security", "daemon_dilithium_priv.bin") as default
parameter values. Default parameter values are evaluated at class
definition time, not at instantiation time. If resolve_path fails during
module import (e.g., because the runtime directory doesn’t exist yet),
the class definition itself crashes and the module can’t be imported at
all.

53. security_daemon.py _run_inotify_loop accesses
inotify.watches[e.wd].path. The inotify_simple library’s INotify
object doesn’t have a .watches dict attribute. Watch descriptors and
paths aren’t tracked by the library — the caller is responsible for
maintaining a mapping. This throws AttributeError on the first inotify
event. The inotify code path is completely non-functional.

54. security_daemon.py _analyze_file return type annotation says
(bool, Optional[str], Dict[str, Any]) but uses the legacy tuple
syntax, not tuple[...] or Tuple[...]. More importantly, it returns
a bare -> arrow with parenthesized types that Python interprets as a
tuple expression, not a type annotation. This doesn’t cause a runtime
error but it means static type checkers and IDE tooling can’t validate
the return types.

55. security_daemon.py _get_intrusion_source_for_file returns an
intrusion source for EVERY file. The fallback else branch returns
{"type": "ip", "value": f"{base}"} for any filename that doesn’t
match the prefixes. This means every file that’s scanned — even benign
ones — gets tagged with an “intrusion source” of ip:<filename>. If
autoban is enabled, every file update would attempt to ban its own
filename as an IP address.

56. pqc_tls.py _set_supported_groups tries to access ctx._sslctx or
ctx._context to get a raw SSL_CTX pointer. These are private CPython
implementation details that vary between Python versions. In Python
3.10+ the internal structure changed. There’s no guarantee either
attribute exists or is an integer. If neither is found, the function
raises OSError, which in non-strict mode means groups aren’t set, and
the connection falls back to whatever OpenSSL defaults to — which may
or may not include PQC groups.

57. pqc_tls.py uses cffi to call SSL_get_shared_group but the CFFI
definitions use typedef ... SSL; which is an opaque type declaration.
The cast _ffi.cast("SSL*", real_ssl) attempts to cast a Python
integer to an opaque CFFI pointer. This depends on the integer actually
being a valid memory address pointing to an SSL structure — but
there’s no mechanism to extract that address from Python’s ssl module.
real_ssl is likely never a valid integer, making this entire function
inert.

58. pqc_tls_verify.py log_tls_verification_event calls
audit_chain.append_event(event, metadata) on the module import. Same
issue as #2 — audit_chain is imported as a module, not an instance,
and there’s no module-level append_event function.

59. pqc_tls_verify.py verify_negotiated_pqc — the classical mode
check with strict_transport=True rejects the session. But the docstring
and config.py _validate_coherence both say strict_transport=True +
allow_classical_fallback=True is a contradiction that raises
ConfigError. So if strict_transport is True, tls_mode should never be
classical (because that would require classical fallback). But there’s
no enforcement preventing someone from setting tls_mode=classical and
strict_transport=True with allow_classical_fallback=False. The coherence
check only catches strict_transport + allow_classical_fallback, not
strict_transport + tls_mode=classical. This config combination silently
kills all TLS connections.

60. logging_setup.py LockingRotatingFileHandler.doRollover calls
self._lock_file(self.stream) at the start, then calls
super().doRollover() which closes and reopens self.stream. After
super().doRollover(), the old self.stream file handle is closed, but the
finally block calls self._unlock_file(self.stream) on the NEW stream
— which was never locked. On Unix with fcntl.flock, unlocking an
unlocked file is a no-op, but on Windows with msvcrt.locking, this could
throw an error.

61. logging_setup.py LockingRotatingFileHandler._lock_file and
_unlock_file lock exactly 1 byte with msvcrt.locking(..., 1). But the
log file can be any size. This locks only the byte at the current file
position. If two processes are writing to different positions, the lock
doesn’t prevent interleaved writes. The Windows locking is effectively
non-functional for its intended purpose of preventing concurrent
corruption.

62. logging_setup.py doRollover opens the new log file, writes a
LOG_ROTATED JSON event, then also calls audit_chain.append_event(...).
Same module-level function call problem as #2. Additionally, this runs
inside the file handler’s own rollover logic — if the audit chain
append somehow triggers a log event (which it does, since the chain
calls logger.info(...) internally), you get reentrant logging during
rollover. The file handler is mid-rollover while the chain’s logger
tries to write through it.

63. directory_contract.py resolve_path performs symlink checks by
calling os.lstat() and os.path.islink(). But the path components are
being built up iteratively. If an intermediate directory is a symlink
pointing outside the runtime base, os.lstat correctly detects it.
However, if the symlink target is itself a symlink (chained symlinks),
only one level of resolution is checked. candidate.resolve() follows all
symlinks, but current is set to real_target only for the immediate
symlink, and subsequent path components are appended to the resolved
target — which might enable a TOCTOU race if the symlink target is
modified between the lstat check and the resolve call.

64. directory_contract.py resolve_path final check uses string
comparison: str(final_resolved).startswith(str(SENTINEL_RUNTIME_BASE)).
String prefix matching for path containment is a known vulnerability. If
SENTINEL_RUNTIME_BASE is /opsec/aepok_sentinel/runtime, then a path like
/opsec/aepok_sentinel/runtime_evil/ would pass the startswith check.
Should use Path.is_relative_to() (Python 3.9+) or compare resolved
parents.

65. azure_client.py makes HTTP requests to Azure Key Vault but never
sets authentication headers. There’s no Bearer token, no managed
identity token acquisition, no DefaultAzureCredential usage, no auth of
any kind. Every get_secret, set_secret, and delete_secret call will
receive a 401 from Azure. The Azure integration is entirely
non-functional.

66. azure_client.py get_secret parses the response as resp.json() and
returns data.get("value", ""). But Azure Key Vault’s secret API
returns secrets under the path /secrets/{name}/{version} with an API
version query parameter (e.g., ?api-version=7.4). The URL constructed is
just {base_url}/secrets/{secret_name} with no API version. Even with
auth, Azure would return a 400 or redirect.

67. controller.py _init_audit_chain passes pqc_priv and pqc_pub dicts
to AuditChain(). pqc_priv["dilithium"] comes from
local_keys.get("dilithium_priv"). If fetch_current_keys() fails in
permissive mode and returns an empty dict,
local_keys.get("dilithium_priv") is None. The chain is initialized
with None as the Dilithium private key. Every sign_content_bundle call
in the chain then passes None to oqs.Signature("Dilithium2", None),
which will crash.

68. controller.py _init_autoban constructs AutobanManager(self.config,
self.license_mgr, self.audit_chain). But AutobanManager.__init__
takes config, license_mgr, audit_chain, blocklist_file,
sign_priv_key_path — the last two have defaults, but those defaults
point to paths that may not exist. More critically, if self.audit_chain
is None (from #67 pathway), autoban still initializes but any
_append_chain_event call will try self.audit_chain.append_event(...)
on None.

69. controller.py _chain_event doesn’t check if self.audit_chain is
None before accessing it. Wait — it does check if self.audit_chain:.
But the boot() method calls
self._chain_event(EventCode.CONTROLLER_BOOT, ...) after
_init_audit_chain(). If the audit chain initialization failed and
self.audit_chain is None, the event is silently dropped. The controller
boot event — the most important audit trail entry — is lost without
any error or warning.

70. key_manager.py rotate_keys checks rotation_interval_days but never
compares against the last rotation timestamp. It only checks if the
value is <= 0 to disable rotation. There’s no logic to determine WHEN
the last rotation happened. Calling rotate_keys() always rotates
regardless of the interval setting. The rotation_interval_days config
field is effectively meaningless — it’s either “never rotate” (<=0)
or “rotate every time this method is called.”

71. key_manager.py _find_latest_key searches for files with names
starting with the prefix. But after provisioning, the vendor keys are
named vendor_dilithium_priv.bin and vendor_dilithium_pub.pem — without
timestamps. After the first rotation, rotated keys get timestamp
suffixes. _find_latest_key("kyber_priv", ".bin") would match both
the original and timestamped versions. But
_find_latest_key("dilithium_priv", ".bin") would match
vendor_dilithium_priv.bin too, since it starts with dilithium_priv…
wait, no. vendor_dilithium_priv.bin starts with vendor_, not
dilithium_priv. The naming convention is inconsistent between
provisioning (vendor_dilithium_priv) and rotation (dilithium_priv). The
rotated keys are never found alongside the vendor keys because they have
different prefixes.

72. config.py SentinelConfig.__init__ sets self.license_path using
_apply_license_path_contract which may return a string. But license.py
LicenseManager.__init__ also sets its own self.license_path from
resolve_path("license", "license.key") and optionally overrides from
config.raw_dict["license_path"]. There are now two potential license
paths — one on the config object and one on the license manager —
that may disagree. The config’s path is never actually used by the
license manager.

73. provision_device.py collect_user_input hardcodes a config dict with
"cloud_keyvault_url", "cloud_dilithium_secret",
"cloud_kyber_secret", "license_required", "bound_to_hardware", and
"allow_unknown_keys". But per #34, most of these keys aren’t in the
known_keys set of SentinelConfig._check_for_unknown_keys, and
allow_unknown_keys defaults to False. Passing this config to
SentinelConfig throws ConfigError for unknown keys. The provisioner
can’t create a valid config using its own output.

74. provision_device.py imports from aepok_sentinel.core.pqc_crypto
import sign_content_bundle, CryptoSignatureError, oqs. The oqs imported
here is the module-level variable from pqc_crypto.py, which is None if
liboqs isn’t installed. generate_keys() checks if not oqs: raise
ProvisionError(...) — but then immediately does from oqs import
Signature as a direct package import. If oqs the package exists but
pqc_crypto’s import failed for some other reason, the not oqs check is
wrong. If pqc_crypto’s oqs is None because the import genuinely failed,
the from oqs import Signature will also fail. The dual import path is
redundant and confusing.

75. issue_offline_license.py constructs SentinelConfig with
{"schema_version": 1, "mode": "offline"}. "offline" is not in
the valid modes list (scif, airgap, cloud, demo, watch-only).
SentinelConfig._validate_mode() raises ConfigError. The license
generator crashes before it can sign anything.

76. issue_offline_license.py constructs a second SentinelConfig with
{"schema_version": 1, "mode": "cloud"} when using Azure. This one
passes mode validation, but _validate_coherence checks
strict_transport + allow_classical_fallback. With defaults,
allow_classical_fallback=True and strict_transport=False, so it passes.
But SentinelConfig.__init__ also accesses
raw_dict["schema_version"] and raw_dict["mode"] directly, then
accesses optional fields from raw_dict.get(...). Missing fields like
tls_mode won’t be set as attributes (per #8), so any code path touching
config.tls_mode from the Azure client will crash.

77. status_printer.py accesses config.cloud_keyvault_url which is never
set as an attribute on SentinelConfig. It’s only in raw_dict if the user
configured it. AttributeError whenever status is printed in cloud mode.

78. malware_db.py _build_requests_session defines PQCPoolManager as a
nested class inside the method, with _new_pool overriding the parent.
But PoolManager._new_pool’s signature varies across urllib3 versions.
If the installed urllib3 version doesn’t match the expected signature
(especially the request_context parameter), this override either
silently doesn’t apply or crashes. Same nested class pattern exists in
azure_client.py — duplicated code with the same fragility.

79. malware_db.py _build_requests_session reassigns
adapter.init_poolmanager to a lambda. But init_poolmanager is called by
HTTPAdapter.send() during request execution, and by this point the
adapter has already been mounted on the session. The lambda replaces the
method, but HTTPAdapter.__init__ may have already called
init_poolmanager in some versions of requests/urllib3. The PQC context
may never actually be applied to connections.

80. No __init__.py files are visible or mentioned anywhere. The
import paths throughout the codebase assume a package structure (from
aepok_sentinel.core.config import ...). Without __init__.py files
in aepok_sentinel/, aepok_sentinel/core/, aepok_sentinel/utils/, none of
these imports resolve in standard Python. The repo has a setup.py and
pyproject.toml which might declare packages, but implicit namespace
packages behave differently across Python versions and installation
methods.