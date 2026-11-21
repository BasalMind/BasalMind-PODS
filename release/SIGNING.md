# Signing a pod release

Every release needs two Ed25519 signatures from two different public keys:

| Key id | Where it lives | Who can use it |
|---|---|---|
| `ci-1` | Google Cloud KMS `basalmind-pod-release/pod-release-ci` | Only the `Release (build + CI signature)` workflow, on `main` of this repo |
| `hw-1` | A YubiKey (PIV slot 9c, generated on the device) | Only the person holding it, with the PIN and a touch |

The two public keys are pinned in `release/keys.json` (this repo) and in core's `pod_release_pins.json`. Pods do not check release keys themselves. BasalMind verifies both signatures before it uploads a release.

## 1. Build and CI-sign (GitHub)

Actions -> **Release (build + CI signature)** -> Run workflow on `main`, with the release number. The run:
- tests and bundles the release;
- signs it with `ci-1`, and checks that signature before writing it;
- uploads the artifact `pod-release-<n>`, which contains `manifest.json`, `bundle/`, `payload.bin` and `commit.txt`.

## 2. Hardware signature (your Mac)

One-time setup:

```
python3 -m venv ~/.pod-release && ~/.pod-release/bin/pip install yubikey-manager
curl -fsSLO https://raw.githubusercontent.com/BasalMind/BasalMind-PODS/main/release/yubikey_sign.py
```

For each release:

1. Download the artifact, then sign:
   ```
   gh run download <run id> -R BasalMind/BasalMind-PODS -n pod-release-<n>
   ~/.pod-release/bin/python yubikey_sign.py sign manifest.json
   ```
2. The script:
   - refuses any manifest without a valid `ci-1` signature;
   - shows what you are signing;
   - asks for `yes`, then your PIN, then a touch;
   - checks the new signature against the YubiKey's own public key.
3. Paste the printed signature (128 hex characters) to whoever attaches it:
   ```
   node release/release.mjs attach --manifest manifest.json --key-id hw-1 --sig <hex> --expect-pubkey <hw-1 public key>
   node release/release.mjs verify --manifest manifest.json
   ```

To print the YubiKey's public key, which is what gets pinned:

```
~/.pod-release/bin/python yubikey_sign.py pubkey
```
