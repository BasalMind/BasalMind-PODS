#!/usr/bin/env python3
"""Hardware release signature (key id hw-1): a YubiKey only Jonah holds (2026-11-21).

Setup once (macOS):
    python3 -m venv ~/.pod-release && ~/.pod-release/bin/pip install yubikey-manager
Commands:
    ~/.pod-release/bin/python yubikey_sign.py pubkey
        prints the public key of PIV slot 9c as 64 hex characters (this is what gets pinned)
    ~/.pod-release/bin/python yubikey_sign.py sign manifest.json
        shows what is being signed, refuses unless the CI signature (ci-1) verifies, asks for the
        PIN, waits for a touch, checks the new signature against the YubiKey's own public key, and
        prints the signature (128 hex characters) to paste back. The manifest file is not changed.

The bytes signed are exactly release.mjs signingPayload():
    "basalmind-pod-release-v1\\n" + canonical JSON of the manifest without "signatures"
(the same canonical JSON as schema/canonical.js and core's pod_release.canonical_json).
Nothing secret is printed; the private key never leaves the YubiKey.
"""
import getpass
import hashlib
import json
import sys

RELEASE_TAG = "basalmind-pod-release-v1"
CI_KEY_ID = "ci-1"
# Public half of the CI key (GCP KMS pod-release-ci v1, created 2026-11-21). Public, not a secret.
CI_PUBKEY_HEX = "125b7a05a4bcf0469e0dd4db46a3526b7eb8e31fbf4536dea1224ae3724c1bef"
FORBIDDEN_STEP_KEYS = ("deleted_classes", "renamed_classes", "transferred_classes")


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def signing_payload(manifest: dict) -> bytes:
    rest = {k: v for k, v in manifest.items() if k != "signatures"}
    return (RELEASE_TAG + "\n" + canonical_json(rest)).encode("utf-8")


def _verify(pub_hex: str, sig_hex: str, payload: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


def check_manifest(manifest: dict, ci_pubkey_hex: str = CI_PUBKEY_HEX) -> bytes:
    """Returns the payload, or raises SystemExit with a plain reason."""
    if manifest.get("format") != RELEASE_TAG:
        raise SystemExit("not a pod release manifest")
    for step in manifest.get("migrations") or []:
        if any(isinstance(step, dict) and step.get(k) for k in FORBIDDEN_STEP_KEYS):
            raise SystemExit("refused: a migration would destroy pod storage")
    payload = signing_payload(manifest)
    ci = [s for s in manifest.get("signatures") or [] if s.get("key_id") == CI_KEY_ID]
    if len(ci) != 1 or not _verify(ci_pubkey_hex, str(ci[0].get("sig", "")), payload):
        raise SystemExit("refused: no valid CI signature (ci-1). Only sign a manifest built and signed by the release workflow on main.")
    return payload


def _public_hex(public_key) -> str:
    from cryptography.hazmat.primitives import serialization
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _piv():
    from ykman.device import list_all_devices
    from yubikit.core.smartcard import SmartCardConnection
    devices = list_all_devices()
    if len(devices) != 1:
        raise SystemExit(f"plug in exactly one YubiKey (found {len(devices)})")
    device, info = devices[0]
    return device.open_connection(SmartCardConnection), info


def _slot_key(piv):
    from yubikit.piv import KEY_TYPE, SLOT
    meta = piv.get_slot_metadata(SLOT.SIGNATURE)
    if meta.key_type != KEY_TYPE.ED25519:
        raise SystemExit(f"slot 9c holds {meta.key_type.name}, not ED25519 (see RELEASE-KEYS-SETUP Part A)")
    if not meta.generated:
        raise SystemExit("slot 9c key was imported, not generated on the YubiKey: refused")
    return meta


def cmd_pubkey() -> None:
    from yubikit.piv import PivSession
    conn, info = _piv()
    with conn:
        meta = _slot_key(PivSession(conn))
        print(f"YubiKey firmware {info.version}, slot 9c ED25519 (generated on device)")
        print(_public_hex(meta.public_key))


def cmd_sign(path: str) -> None:
    from yubikit.piv import KEY_TYPE, SLOT, PivSession
    with open(path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    payload = check_manifest(manifest)
    modules = (manifest.get("worker") or {}).get("modules") or []
    print(f"release {manifest.get('release')}  spec {manifest.get('spec_cid')}")
    print(f"{len(modules)} worker module(s), {len(manifest.get('panel_assets') or {})} panel asset(s), "
          f"migrations {[m.get('tag') for m in manifest.get('migrations') or []]}")
    print(f"CI signature ci-1: valid.  payload {len(payload)} bytes, sha256 {hashlib.sha256(payload).hexdigest()}")
    if any(s.get("key_id") == "hw-1" for s in manifest.get("signatures") or []):
        raise SystemExit("this manifest already carries an hw-1 signature")
    if input("Sign this release with the YubiKey? Type yes: ").strip().lower() != "yes":
        raise SystemExit("not signed")
    conn, _info = _piv()
    with conn:
        piv = PivSession(conn)
        meta = _slot_key(piv)
        piv.verify_pin(getpass.getpass("YubiKey PIV PIN: "))
        print("Touch the YubiKey now...")
        sig = piv.sign(SLOT.SIGNATURE, KEY_TYPE.ED25519, payload, None)
    pub = _public_hex(meta.public_key)
    if not _verify(pub, sig.hex(), payload):
        raise SystemExit("the YubiKey's signature did not verify against its own public key: not used")
    print(f"hw-1 public key: {pub}")
    print("hw-1 signature (paste this back):")
    print(sig.hex())


def main(argv) -> None:
    if argv[:1] == ["pubkey"] and len(argv) == 1:
        cmd_pubkey()
    elif argv[:1] == ["sign"] and len(argv) == 2:
        cmd_sign(argv[1])
    else:
        raise SystemExit("usage: yubikey_sign.py pubkey | sign <manifest.json>")


if __name__ == "__main__":
    main(sys.argv[1:])
