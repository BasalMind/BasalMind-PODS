"""Generates test/vectors/did_log_vectors.json using BasalMind core's Python
did:webvh verifier (BasalTribe/basaltribe/pod_did_verifier.py) as the
reference: builds valid and tampered logs, runs the Python verify_log() on
each, and records accept/reject. test/did-log-verifier.test.js asserts the JS
verifier (src/did_log.js) agrees on every vector.

Usage (read-only against core):
  python3 test/vectors/gen_vectors.py /opt/basalmind/prod/BasalTribe/basaltribe/pod_did_verifier.py
"""
import copy, hashlib, importlib.util, json, sys
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

spec = importlib.util.spec_from_file_location("pod_did_verifier", sys.argv[1])
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

def key(seed_byte):
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, "z" + v._base58btc_encode(bytes([0xED, 0x01]) + raw)

A, B, C = key(0x71), key(0x72), key(0x73)
mh = v._multikey_hash
b58 = v._base58btc_encode
jcs = v._jcs_canonicalize
def h(obj): return b58(v._multihash_sha256(jcs(obj)))

def sign(entry_no_proof, signer, vm_key=None, purpose="assertionMethod", vm_override=None):
    priv, mk = signer
    opts = {"type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": vm_override or f"did:key:{vm_key or mk}#{vm_key or mk}",
            "created": "2026-10-18T00:00:00Z", "proofPurpose": purpose}
    data = hashlib.sha256(jcs(opts)).digest() + hashlib.sha256(jcs(entry_no_proof)).digest()
    return {**opts, "proofValue": "z" + b58(priv.sign(data))}

def genesis(update_keys, next_hashes, signer, extra_state=None, domain="example.com:p:abc", **signkw):
    state = {"id": f"did:webvh:{{SCID}}:{domain}", **(extra_state or {})}
    params = {"method": "did:webvh:1.0", "scid": "{SCID}", "updateKeys": update_keys, "portable": True}
    if next_hashes is not None: params["nextKeyHashes"] = next_hashes
    prelim = {"versionId": "{SCID}", "versionTime": "2026-10-18T00:00:00Z", "parameters": params, "state": state}
    scid = h(prelim)
    e = v._substitute_literal(prelim, "{SCID}", scid)
    e["versionId"] = scid
    e["versionId"] = "1-" + h(e)
    e["proof"] = [sign({k: x for k, x in e.items()}, signer, **signkw)] if signer else []
    if not signer: del e["proof"]
    return scid, e

def append(log, params, state_extra, signer, **signkw):
    prev = log[-1]
    did = prev["state"]["id"]
    e = {"versionId": prev["versionId"], "versionTime": "2026-10-18T01:00:00Z", "parameters": params,
         "state": {"id": did, **state_extra}}
    n = len(log) + 1
    e["versionId"] = f"{n}-{h(e)}"
    e["proof"] = [sign({k: x for k, x in e.items()}, signer, **signkw)]
    return log + [e]

cases = []
def add(name, did, log, expected_disagreement=None):
    try:
        v.verify_log(did, log); ok = True
    except Exception:  # core treats any exception as reject
        ok = False
    c = {"name": name, "did": did, "log": log, "valid": ok}
    if expected_disagreement:
        c["expected_disagreement"] = expected_disagreement
    cases.append(c)

def proof_of(entry, signer, **kw):
    return sign({k: x for k, x in entry.items() if k != "proof"}, signer, **kw)

def base(next_hashes=None, signer=A, **kw):
    scid, g = genesis([A[1]], next_hashes, signer, **kw)
    return scid, g["state"]["id"], [g]

# --- valid
scid, did, log = base(next_hashes=[mh(B[1])]); add("valid_genesis_only", did, log)
scid, did, log = base(next_hashes=[])
add("valid_same_keys_state_change", did, append(log, {}, {"service": [{"id": "#pod", "type": "PodService"}]}, A))
scid, did, log = base()
add("valid_plain_rotation", did, append(log, {"updateKeys": [B[1]]}, {}, A))
scid, did, log = base(next_hashes=[mh(B[1])])
add("valid_prerotation", did, append(log, {"updateKeys": [B[1]], "nextKeyHashes": [mh(C[1])]}, {}, B))
scid, did, log = base(next_hashes=[])
add("valid_unicode_state", did, append(log, {}, {"alsoKnownAs": ["café ü"]}, A))
# --- tampered
scid, did, log = base(next_hashes=[]); l2 = append(log, {}, {}, A)
t = copy.deepcopy(l2); t[0]["state"]["extra"] = "tamper"; add("tamper_genesis_state", did, t)
t = copy.deepcopy(l2); t[1]["parameters"]["updateKeys"] = [C[1]]; add("tamper_entry2_params", did, t)
t = copy.deepcopy(l2); t[1]["versionId"] = "3-" + t[1]["versionId"].split("-", 1)[1]; add("wrong_version_number", did, t)
add("reordered_entries", did, [l2[1], l2[0]])
add("scid_mismatch_in_did", did.replace(scid, "QmNotTheScid"), l2)
t = copy.deepcopy(l2); del t[1]["proof"]; add("missing_proof", did, t)
t = copy.deepcopy(l2); t[1]["proof"] = []; add("empty_proof", did, t)
add("entry2_signed_by_unauthorized_key", did, append(log, {}, {}, B))
add("entry2_bad_signature_claims_A", did, append(log, {}, {}, C, vm_key=A[1]))
add("entry2_wrong_purpose", did, append(log, {}, {}, A, purpose="authentication"))
add("entry2_vm_fragment_mismatch", did, append(log, {}, {}, A, vm_override=f"did:key:{A[1]}#{B[1]}"))
add("entry2_vm_not_did_key", did, append(log, {}, {}, A, vm_override=f"did:web:example.com#{A[1]}"))
scid, did, log = base(next_hashes=[])
t = append(log, {}, {}, A); t[1]["state"]["id"] = "did:webvh:" + scid + ":evil.example:p:abc"
add("latest_state_id_mismatch_unsigned", did, t)
scid, g = genesis([A[1]], [], B); add("genesis_signed_by_non_updatekey", g["state"]["id"], [g])
scid, g = genesis([A[1]], [], None); add("genesis_no_proof", g["state"]["id"], [g])
# pre-rotation violations
scid, did, log = base(next_hashes=[mh(B[1])])
add("prerotation_uncommitted_key", did, append(log, {"updateKeys": [C[1]], "nextKeyHashes": [mh(A[1])]}, {}, C))
add("prerotation_missing_next_key_hashes", did, append(log, {"updateKeys": [B[1]]}, {}, B))
add("prerotation_missing_update_keys", did, append(log, {"nextKeyHashes": [mh(C[1])]}, {}, A))
add("prerotation_signed_by_old_key", did, append(log, {"updateKeys": [B[1]], "nextKeyHashes": [mh(C[1])]}, {}, A))

# --- non-array key parameters (JS must reject like Python)
scid, g = genesis([A[1]], "junk", A); l = append([g], {}, {}, A)
add("next_key_hashes_string_then_omitted", g["state"]["id"], l)
scid, g = genesis([A[1]], [], A); g2 = copy.deepcopy(g); g2["parameters"]["updateKeys"] = A[1]
add("update_keys_is_string", g2["state"]["id"], [g2])
# --- rotation A->B, then an entry signed by A (old key) is rejected; by B accepted
scid, did, log = base()
rot = append(log, {"updateKeys": [B[1]]}, {}, A)
add("after_rotation_entry_signed_by_old_key", did, append(rot, {}, {}, A))
add("after_rotation_entry_signed_by_new_key", did, append(rot, {}, {}, B))
# --- multi-proof
scid, did, log = base(next_hashes=[])
e2 = append(log, {}, {}, A); good = e2[-1]["proof"][0]
bad = proof_of(e2[-1], C, vm_key=A[1])  # claims A, signed by C
malformed = {"type": "DataIntegrityProof"}
for name, proofs in [("multi_proof_bad_then_good", [bad, good]), ("multi_proof_good_then_malformed", [good, malformed]),
                     ("multi_proof_malformed_then_good", [malformed, good]), ("multi_proof_all_bad", [bad, bad])]:
    t = copy.deepcopy(e2); t[-1]["proof"] = proofs; add(name, did, t)
# --- pre-rotation deactivation sequence
scid, did, log = base(next_hashes=[mh(B[1])])
deact = append(log, {"updateKeys": [B[1]], "nextKeyHashes": []}, {}, B)
add("deactivate_prerotation_then_free_rotation", did, append(deact, {"updateKeys": [C[1]]}, {}, B))
add("deactivate_prerotation_then_signed_by_new_key", did, append(deact, {"updateKeys": [C[1]]}, {}, C))
# --- __proto__ key in state must not change the verdict
scid, did, log = base(next_hashes=[])
t = copy.deepcopy(log); st = {"id": did, "__proto__": {"x": 1}}
# build properly signed entry 2 containing a literal "__proto__" key
e = {"versionId": log[-1]["versionId"], "versionTime": "2026-10-18T01:00:00Z", "parameters": {}, "state": st}
e["versionId"] = "2-" + h(e); e["proof"] = [proof_of(e, A)]
add("proto_key_in_state", did, log + [e])
# --- KNOWN DISAGREEMENT: non-BMP vs high-BMP sibling keys (core sorts by code point, RFC 8785 by UTF-16)
scid, g = genesis([A[1]], [], A, extra_state={"\ufb01": 1, "\U0001F600": 2})
add("nonbmp_key_order_known_disagreement", g["state"]["id"], [g], expected_disagreement="core sorts keys by code point; RFC 8785 (JS) by UTF-16 code unit. Core bug filed separately")

json.dump({"keys": {"A": A[1], "B": B[1], "C": C[1]}, "cases": cases}, open("test/vectors/did_log_vectors.json", "w"), indent=1)
for c in cases: print(("ACCEPT " if c["valid"] else "REJECT ") + c["name"])
