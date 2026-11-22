#!/usr/bin/env python3
"""Deterministic generator for Amendment A11 conformance test vectors (33 cases).

Generates `amendments/a11/cases/<case-name>/{bundle.json, case.json, expected-report.json}`
using deterministic Ed25519 keys, RFC 8785 / Core C1 canonical JSON, and valid DSSE envelopes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BASE_DEFS_DIR = REPO_ROOT / "definitions"
A11_DIR = REPO_ROOT / "amendments" / "a11"
A11_DEFS_DIR = A11_DIR / "definitions"
CASES_OUT_DIR = A11_DIR / "cases"

PAYLOAD_TYPE = "application/vnd.r5e.provenance-evidence+json;v=2"
DEPLOYMENT_NAME = "a11-vectors"
START_STREAM = f"urn:r5e:stream:{DEPLOYMENT_NAME}:start"
AUTH_STREAM = f"urn:r5e:stream:{DEPLOYMENT_NAME}:authority"
PUB_STREAM = f"urn:r5e:stream:publisher:{DEPLOYMENT_NAME}"
GOV_STREAM = f"urn:r5e:stream:{DEPLOYMENT_NAME}:governance"
SESS_STREAM = f"urn:r5e:stream:{DEPLOYMENT_NAME}:session:01"
CKPT_STREAM = f"urn:r5e:stream:{DEPLOYMENT_NAME}:checkpoints"

INSTITUTION_URI = "urn:r5e:org:example-institution"
PERSON_1_URI = "urn:r5e:subject:person-1"
PERSON_2_URI = "urn:r5e:subject:person-2"
WORKLOAD_URI = "urn:r5e:workload:batch-1"
RECIPIENT_URI = "urn:r5e:recipient:auditor-1"
SESSION_1_URI = "urn:r5e:session:a11-0001"
SESSION_W_URI = "urn:r5e:session:a11-workload-0001"


def encode_canonical_json(value: Any) -> bytes:
    """RFC 8785 / Core C1 canonical JSON encoding."""
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if type(value) is int:
        return str(value).encode("ascii")
    if type(value) is str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(encode_canonical_json(item) for item in value) + b"]"
    if isinstance(value, dict):
        items = []
        for k in sorted(value.keys(), key=lambda s: s.encode("utf-16-be")):
            k_bytes = json.dumps(k, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            items.append(k_bytes + b":" + encode_canonical_json(value[k]))
        return b"{" + b",".join(items) + b"}"
    raise TypeError(f"Unsupported type for canonical JSON: {type(value)}")


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def bytes_ref(raw: bytes) -> str:
    return "bytes:sha256:" + sha256_hex(raw)


def salted_ref(salt: bytes, plaintext: bytes) -> str:
    assert len(salt) == 32
    return "bytes:sha256+salt:" + sha256_hex(b"r5e-salted-content-v1\x00" + salt + plaintext)


def compute_key_id(alg: str, raw_pub: bytes) -> str:
    alg_bytes = alg.encode("ascii")
    digest = sha256_hex(bytes([len(alg_bytes)]) + alg_bytes + raw_pub)
    return f"key:{alg}:sha256:{digest}"


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(pt)).encode("ascii")
        + b" "
        + pt
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


@dataclass(frozen=True)
class KeyPair:
    name: str
    priv: Ed25519PrivateKey
    pub_raw: bytes
    keyid: str

    @classmethod
    def from_seed_name(cls, name: str) -> KeyPair:
        seed = hashlib.sha256(f"r5e-a11-vector-key:{name}".encode("utf-8")).digest()
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pub_raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return cls(name=name, priv=priv, pub_raw=pub_raw, keyid=compute_key_id("ed25519", pub_raw))

    def sign(self, msg: bytes) -> str:
        return b64(self.priv.sign(msg))

    def public_key_obj(self) -> dict[str, str]:
        return {"algorithm": "ed25519", "bytes": b64(self.pub_raw)}

    def bundle_entry(self) -> dict[str, str]:
        return {"algorithm": "ed25519", "bytes": b64(self.pub_raw), "keyid": self.keyid}


# Deterministic key set shared across all 33 vectors
KEYS: dict[str, KeyPair] = {
    name: KeyPair.from_seed_name(name)
    for name in [
        "publisher",
        "bootstrap",
        "root",
        "institution",
        "person1",
        "person1_new",
        "device_session",
        "approver_hw",
        "approver_file",
        "recipient",
        "witness",
        "rogue_witness",
        "overseer",
        "recovery_1",
        "recovery_2",
        "recovery_3",
        "copy_a",
        "copy_b",
        "copy_unknown",
        "checkpoint",
        "operator",
    ]
}


def load_all_definitions() -> tuple[dict[str, tuple[str, bytes]], dict[str, tuple[str, bytes]]]:
    base_index = json.loads((BASE_DEFS_DIR / "index.json").read_text(encoding="utf-8"))
    base_defs: dict[str, tuple[str, bytes]] = {}
    for kind, expected_ref in sorted(base_index.items()):
        raw = (BASE_DEFS_DIR / f"{kind}.json").read_bytes()
        assert bytes_ref(raw) == expected_ref, f"Baseline digest mismatch: {kind}"
        base_defs[kind] = (expected_ref, raw)

    a11_index = json.loads((A11_DEFS_DIR / "index.json").read_text(encoding="utf-8"))
    a11_defs: dict[str, tuple[str, bytes]] = {}
    for item in a11_index:
        raw = (A11_DEFS_DIR / item["file"]).read_bytes()
        assert bytes_ref(raw) == item["schemaRef"], f"A11 digest mismatch: {item['kind']}"
        a11_defs[item["kind"]] = (item["schemaRef"], raw)

    return base_defs, a11_defs


BASE_DEFS, A11_DEFS = load_all_definitions()
MERGED_SCHEMAS: dict[str, str] = {
    **{k: v[0] for k, v in BASE_DEFS.items()},
    **{k: v[0] for k, v in A11_DEFS.items()},
}


class BundleBuilder:
    """Helper for constructing valid canonical r5e.provenance-export/v2 bundles."""

    def __init__(self, custody_level: int = 2, sealed_copies: list[str] | None = None) -> None:
        self.custody_level = custody_level
        self.sealed_copies = sealed_copies if sealed_copies is not None else ["copy-a", "copy-b"]
        self.records: list[dict[str, Any]] = []
        self.blobs: dict[str, bytes] = {}
        self.keys: dict[str, KeyPair] = {}
        self.stream_seq: dict[str, int] = {}
        self.stream_prev: dict[str, str] = {}
        self.checkpoints: list[str] = []
        self.salted_content: dict[str, dict[str, str]] = {}
        self.witness_receipts: dict[str, dict[str, Any]] = {}
        self.unlock_log: list[dict[str, Any]] = []
        self.pinned_checkpoints: list[dict[str, Any]] = []
        self.trusted_profiles: list[str] = []
        self.chain_ref: str | None = None

        self._init_profiles_and_start()

    def add_key(self, kp: KeyPair) -> None:
        self.keys[kp.keyid] = kp

    def add_blob(self, raw: bytes) -> str:
        ref = bytes_ref(raw)
        self.blobs[ref] = raw
        return ref

    def _make_profile(self, bindings: list[dict[str, Any]], schemas: dict[str, str]) -> str:
        policy_ref = self.add_blob(b'{"policy":"a11-conformance-vectors"}')
        profile = {
            "authority": {
                "bindings": bindings,
                "checkpointKeys": [KEYS["checkpoint"].keyid],
            },
            "deploymentPolicyRef": policy_ref,
            "durability": {
                "failureDomain": "conformance vectors",
                "onFailure": "refuse",
                "requiredPayloads": "submitted",
            },
            "format": "r5e.capture-profile/v2",
            "policyRequiredKinds": [],
            "schemas": {k: schemas[k] for k in sorted(schemas.keys()) if k.startswith("provenance.r5e.io/v2/")},
        }
        pref = self.add_blob(encode_canonical_json(profile))
        if pref not in self.trusted_profiles:
            self.trusted_profiles.append(pref)
        return pref

    def _init_profiles_and_start(self) -> None:
        for kp in [
            KEYS["publisher"],
            KEYS["bootstrap"],
            KEYS["root"],
            KEYS["institution"],
            KEYS["witness"],
            KEYS["overseer"],
            KEYS["checkpoint"],
        ]:
            self.add_key(kp)

        # Carry all 28 baseline definition blobs + 14 A11 definition blobs
        for _, raw in BASE_DEFS.values():
            self.add_blob(raw)
        for _, raw in A11_DEFS.values():
            self.add_blob(raw)

        # Publisher profile (uses baseline schemas)
        self.pub_profile_ref = self._make_profile(
            bindings=[
                {
                    "actorPrefixes": ["urn:r5e:publisher:"],
                    "issuerKeys": [KEYS["publisher"].keyid],
                    "sealerKeys": [],
                    "streamPrefix": PUB_STREAM,
                }
            ],
            schemas={k: v[0] for k, v in BASE_DEFS.items()},
        )

        # Start + operational profile (uses merged A11 schemas)
        all_op_keys = sorted(
            {
                KEYS["bootstrap"].keyid,
                KEYS["root"].keyid,
                KEYS["institution"].keyid,
                KEYS["person1"].keyid,
                KEYS["person1_new"].keyid,
                KEYS["device_session"].keyid,
                KEYS["approver_hw"].keyid,
                KEYS["approver_file"].keyid,
                KEYS["checkpoint"].keyid,
            }
        )
        self.op_profile_ref = self._make_profile(
            bindings=[
                {
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": all_op_keys,
                    "sealerKeys": [],
                    "streamPrefix": f"urn:r5e:stream:{DEPLOYMENT_NAME}:",
                }
            ],
            schemas=MERGED_SCHEMAS,
        )

        # Baseline-only operational profile (for V11 coexistence test)
        self.base_op_profile_ref = self._make_profile(
            bindings=[
                {
                    "actorPrefixes": ["urn:r5e:"],
                    "issuerKeys": all_op_keys,
                    "sealerKeys": [],
                    "streamPrefix": f"urn:r5e:stream:{DEPLOYMENT_NAME}:",
                }
            ],
            schemas={k: v[0] for k, v in BASE_DEFS.items()},
        )

        # Publish 28 baseline definitions (seq 1) and 14 A11 definitions (seq 2)
        pub_base_ref = self.add_record(
            kind="DefinitionPublished",
            stream=PUB_STREAM,
            actor="urn:r5e:publisher:r5e",
            captured_at="2026-11-22T11:00:00Z",
            signers=[KEYS["publisher"]],
            profile_ref=self.pub_profile_ref,
            schema_ref=BASE_DEFS["provenance.r5e.io/v2/DefinitionPublished"][0],
            body={
                "definitions": [
                    {"definition": ref, "kind": kind} for kind, (ref, _) in sorted(BASE_DEFS.items())
                ]
            },
        )
        self.add_record(
            kind="DefinitionPublished",
            stream=PUB_STREAM,
            actor="urn:r5e:publisher:r5e",
            captured_at="2026-11-22T11:00:01Z",
            signers=[KEYS["publisher"]],
            profile_ref=self.pub_profile_ref,
            schema_ref=BASE_DEFS["provenance.r5e.io/v2/DefinitionPublished"][0],
            body={
                "definitions": [
                    {"definition": ref, "kind": kind} for kind, (ref, _) in sorted(A11_DEFS.items())
                ]
            },
        )

        # ChainStarted (seq 1)
        cs_ref = self.add_record(
            kind="ChainStarted",
            stream=START_STREAM,
            actor=f"urn:r5e:node:{DEPLOYMENT_NAME}",
            captured_at="2026-11-22T11:01:00Z",
            signers=[KEYS["bootstrap"]],
            profile_ref=self.op_profile_ref,
            schema_ref=BASE_DEFS["provenance.r5e.io/v2/ChainStarted"][0],
            body={
                "bootstrap": KEYS["bootstrap"].keyid,
                "bootstrapKey": KEYS["bootstrap"].public_key_obj(),
                "definitions": [
                    {"definition": ref, "kind": kind} for kind, (ref, _) in sorted(BASE_DEFS.items())
                ],
                "deployment": DEPLOYMENT_NAME,
                "publication": pub_base_ref,
                "publisher": KEYS["publisher"].keyid,
            },
        )

        # Deployment (seq 2, using A11 extended Deployment schema)
        dep_body: dict[str, Any] = {
            "accepts": cs_ref,
            "approverRoles": [
                {"keys": [KEYS["approver_hw"].keyid, KEYS["approver_file"].keyid], "role": "privacy_officer"}
            ],
            "bootstrap": KEYS["bootstrap"].keyid,
            "claimedBy": KEYS["root"].keyid,
            "custodyLevel": self.custody_level,
            "overseerKey": KEYS["overseer"].keyid,
            "roots": [
                {
                    "key": KEYS["root"].keyid,
                    "publicKey": KEYS["root"].public_key_obj(),
                }
            ],
            "sealedServiceCopies": self.sealed_copies,
            "threshold": 1,
            "witnessKeys": [KEYS["witness"].keyid],
        }
        self.chain_ref = self.add_record(
            kind="Deployment",
            stream=START_STREAM,
            actor=f"urn:r5e:node:{DEPLOYMENT_NAME}",
            captured_at="2026-11-22T11:01:05Z",
            signers=[KEYS["bootstrap"], KEYS["root"]],
            profile_ref=self.op_profile_ref,
            schema_ref=A11_DEFS["provenance.r5e.io/v2/Deployment"][0],
            body=dep_body,
        )

        # Endorse institution key
        self.endorse(
            subject_key=KEYS["institution"],
            kinds=[
                "provenance.r5e.io/v2/Basis",
                "provenance.r5e.io/v2/BasisOverlay",
                "provenance.r5e.io/v2/ReleaseRequest",
                "provenance.r5e.io/v2/ReleaseReceipt",
                "provenance.r5e.io/v2/ErasureAnswer",
                "provenance.r5e.io/v2/Observation",
                "provenance.r5e.io/v2/Disclosure",
                "provenance.r5e.io/v2/SessionOpened",
                "provenance.r5e.io/v2/Succession",
            ],
            acts_for=INSTITUTION_URI,
            role="institution_recorder",
            captured_at="2026-11-22T11:02:00Z",
        )

    def add_record(
        self,
        *,
        kind: str,
        stream: str,
        actor: str,
        captured_at: str,
        signers: list[KeyPair],
        body: dict[str, Any],
        profile_ref: str | None = None,
        schema_ref: str | None = None,
        session: str | None = None,
        causes: list[str] | None = None,
        seq_override: int | None = None,
    ) -> str:
        for kp in signers:
            self.add_key(kp)

        seq = seq_override if seq_override is not None else self.stream_seq.get(stream, 0) + 1
        prev = self.stream_prev.get(stream) if seq_override is None else None
        if seq_override is None:
            self.stream_seq[stream] = seq

        full_kind = f"provenance.r5e.io/v2/{kind}"
        s_ref = schema_ref or MERGED_SCHEMAS[full_kind]
        p_ref = profile_ref or self.op_profile_ref

        payload: dict[str, Any] = {
            "actor": actor,
            "apiVersion": "provenance.r5e.io/v2",
            "body": body,
            "capturedAt": captured_at,
            "issuer": signers[0].keyid,
            "kind": kind,
            "profileRef": p_ref,
            "schemaRef": s_ref,
            "seq": seq,
            "stream": stream,
        }
        payload["previous"] = prev
        if session is not None:
            payload["session"] = session
        if causes:
            payload["causes"] = sorted(set(causes))

        payload_bytes = encode_canonical_json(payload)
        rec_ref = "evidence:sha256:" + sha256_hex(payload_bytes)
        pae = dsse_pae(PAYLOAD_TYPE, payload_bytes)
        sigs = [{"keyid": kp.keyid, "sig": kp.sign(pae)} for kp in signers]

        self.records.append(
            {
                "envelope": {
                    "payload": b64(payload_bytes),
                    "payloadType": PAYLOAD_TYPE,
                    "signatures": sigs,
                },
                "ref": rec_ref,
            }
        )
        if seq_override is None:
            self.stream_prev[stream] = rec_ref
        return rec_ref

    def endorse(
        self,
        *,
        subject_key: KeyPair,
        kinds: list[str],
        acts_for: str,
        role: str,
        captured_at: str,
        key_storage: str | None = None,
        hardware_attestation: bytes | None = None,
        signer_kind: str | None = None,
        recovery_rule: dict[str, Any] | None = None,
        use_baseline_schema: bool = False,
    ) -> str:
        self.add_key(subject_key)
        body: dict[str, Any] = {
            "kinds": sorted(set(kinds)),
            "mayEndorse": False,
            "notAfter": "2027-11-22T00:00:00Z",
            "notBefore": "2026-11-01T00:00:00Z",
            "role": role,
            "subject": subject_key.keyid,
        }
        if key_storage is not None:
            body["keyStorage"] = key_storage
        if hardware_attestation is not None:
            body["hardwareAttestationRef"] = self.add_blob(hardware_attestation)
        if signer_kind is not None:
            body["signerKind"] = signer_kind
        if recovery_rule is not None:
            body["recoveryRule"] = recovery_rule

        return self.add_record(
            kind="Endorsement",
            stream=AUTH_STREAM,
            actor=f"urn:r5e:root:{DEPLOYMENT_NAME}",
            captured_at=captured_at,
            signers=[KEYS["root"]],
            profile_ref=self.base_op_profile_ref if use_baseline_schema else self.op_profile_ref,
            schema_ref=(
                BASE_DEFS["provenance.r5e.io/v2/Endorsement"][0]
                if use_baseline_schema
                else A11_DEFS["provenance.r5e.io/v2/Endorsement"][0]
            ),
            body=body,
        )

    def add_basis(
        self,
        *,
        subjects: list[str],
        signers: list[KeyPair],
        actor: str = PERSON_1_URI,
        powers: list[str] | None = None,
        ground_id: str = "g-care",
        declared_terms: list[dict[str, Any]] | None = None,
        explanation_ref: str | None = None,
        captured_at: str = "2026-11-22T12:00:00Z",
        until: str = "2027-11-22T00:00:00Z",
    ) -> str:
        exp_ref = explanation_ref or self.add_blob(b"Plain-language governance explanation v1.")
        pwr_list = powers if powers is not None else ["capture", "keep", "disclose"]
        body: dict[str, Any] = {
            "actor": actor,
            "explanationRef": exp_ref,
            "grounds": [
                {
                    "groundId": ground_id,
                    "instrument": "institutional-custody-policy-v1",
                    "powers": [
                        {
                            "approvalRule": {"roles": ["privacy_officer"], "threshold": 1},
                            "duration": {"until": until},
                            "power": p,
                            "purpose": f"Authorized {p} under {ground_id}",
                        }
                        for p in pwr_list
                    ],
                    "recordClasses": ["session_transcript"],
                }
            ],
            "institution": INSTITUTION_URI,
            "subjects": subjects,
        }
        if declared_terms is not None:
            body["declaredTerms"] = declared_terms

        return self.add_record(
            kind="Basis",
            stream=GOV_STREAM,
            actor=actor,
            captured_at=captured_at,
            signers=signers,
            body=body,
        )

    def sign_release_approval(
        self,
        *,
        approver: KeyPair,
        request_id: str,
        recipient_key: str,
        basis_ref: str,
        contract_version: str,
        tamper: bool = False,
    ) -> dict[str, str]:
        self.add_key(approver)
        msg_obj = {
            "basisFingerprint": basis_ref,
            "contractVersion": contract_version if not tamper else contract_version + "-tampered",
            "recipientKey": recipient_key,
            "requestId": request_id,
        }
        sig = approver.sign(b"r5e-release-approval-v1\x00" + encode_canonical_json(msg_obj))
        return {"role": "privacy_officer", "signature": sig, "signerKey": approver.keyid}

    def add_release_request(
        self,
        *,
        basis_ref: str,
        ground_id: str = "g-care",
        power: str = "disclose",
        targets: list[str] | None = None,
        subjects: list[str] | None = None,
        approver: KeyPair | None = None,
        tamper_sig: bool = False,
        captured_at: str = "2026-11-22T12:02:00Z",
        request_id: str = "req-a11-0123456789abcdef0123456789abcdef",
    ) -> str:
        self.add_key(KEYS["recipient"])
        app_key = approver or KEYS["approver_hw"]
        contract_ver = "v1"
        approval = self.sign_release_approval(
            approver=app_key,
            request_id=request_id,
            recipient_key=KEYS["recipient"].keyid,
            basis_ref=basis_ref,
            contract_version=contract_ver,
            tamper=tamper_sig,
        )
        body: dict[str, Any] = {
            "approvals": [approval],
            "basisRef": basis_ref,
            "contractVersion": contract_ver,
            "groundId": ground_id,
            "power": power,
            "reason": "Authorized audit disclosure",
            "recipient": RECIPIENT_URI,
            "recipientKey": KEYS["recipient"].keyid,
            "requestId": request_id,
            "sealed": False,
            "subjects": subjects if subjects is not None else [PERSON_1_URI],
            "targets": targets if targets is not None else [SESSION_1_URI],
            "timeWindow": {
                "notAfter": "2026-11-23T00:00:00Z",
                "notBefore": "2026-11-22T12:00:00Z",
            },
        }
        return self.add_record(
            kind="ReleaseRequest",
            stream=GOV_STREAM,
            actor=INSTITUTION_URI,
            captured_at=captured_at,
            signers=[KEYS["institution"]],
            body=body,
        )

    def add_witness_receipt(
        self,
        *,
        request_ref: str,
        witness_key: KeyPair | None = None,
        mismatch_hash: bool = False,
        logged_at: str = "2026-11-22T12:02:05Z",
        log_index: int = 0,
    ) -> str:
        wkey = witness_key or KEYS["witness"]
        self.add_key(wkey)
        req_hex = request_ref.split("evidence:sha256:", 1)[1]
        req_hash = "sha256:" + ("0" * 64 if mismatch_hash else req_hex)
        unsigned = {
            "logIndex": log_index,
            "loggedAt": logged_at,
            "requestHash": req_hash,
            "requestRef": request_ref,
            "witnessKey": wkey.keyid,
        }
        sig = wkey.sign(b"r5e-witness-receipt-v1\x00" + encode_canonical_json(unsigned))
        receipt = {**unsigned, "signature": sig}
        receipt_bytes = encode_canonical_json(receipt)
        receipt_ref = self.add_blob(receipt_bytes)
        self.witness_receipts[receipt_ref] = receipt
        return receipt_ref

    def add_release_receipt(
        self,
        *,
        request_ref: str,
        outcome: str,
        released_fingerprint: str | None = None,
        witness_receipt_ref: str | None = None,
        captured_at: str = "2026-11-22T12:02:10Z",
    ) -> str:
        body: dict[str, Any] = {
            "outcome": outcome,
            "recipientKey": KEYS["recipient"].keyid,
            "requestRef": request_ref,
        }
        if released_fingerprint is not None:
            body["releasedFingerprint"] = released_fingerprint
        if witness_receipt_ref is not None:
            body["witnessReceiptRef"] = witness_receipt_ref
        return self.add_record(
            kind="ReleaseReceipt",
            stream=GOV_STREAM,
            actor=INSTITUTION_URI,
            captured_at=captured_at,
            signers=[KEYS["institution"]],
            body=body,
        )

    def build(self) -> tuple[dict[str, Any], dict[str, Any]]:
        bundle: dict[str, Any] = {
            "blobs": [
                {"base64": b64(raw), "ref": ref}
                for ref, raw in sorted(self.blobs.items())
            ],
            "checkpoints": self.checkpoints,
            "format": "r5e.provenance-export/v2",
            "keys": [
                kp.bundle_entry()
                for _, kp in sorted(self.keys.items())
            ],
            "omissions": [],
            "proofs": [],
            "publicationProofs": [],
            "records": self.records,
            "scope": {
                "at": [
                    {"event": self.stream_prev[s], "seq": self.stream_seq[s], "stream": s}
                    for s in sorted(self.stream_seq.keys())
                ],
                "query": {"amendment": "A11"},
            },
            "seals": [],
        }
        if self.salted_content:
            bundle["saltedContent"] = dict(sorted(self.salted_content.items()))
        if self.witness_receipts:
            bundle["witnessReceipts"] = dict(sorted(self.witness_receipts.items()))
        if self.unlock_log:
            bundle["unlockLog"] = self.unlock_log
        if self.pinned_checkpoints:
            bundle["pinnedCheckpoints"] = self.pinned_checkpoints

        case_meta: dict[str, Any] = {
            "minStartSeq": None,
            "trustedChain": self.chain_ref,
            "trustedProfiles": self.trusted_profiles,
            "trustedPublishers": [KEYS["publisher"].keyid],
            "trustedRoots": None,
        }
        return bundle, case_meta


def make_finding(
    *,
    layer: int,
    subject: str,
    check: str,
    result: str,
    code: str,
    category: str,
    about: str | None = None,
) -> dict[str, Any]:
    return {
        "about": about,
        "category": category,
        "check": check,
        "code": code,
        "layer": layer,
        "result": result,
        "subject": subject,
    }


def endorse_hw_approver(b: BundleBuilder) -> None:
    b.endorse(
        subject_key=KEYS["approver_hw"],
        kinds=["provenance.r5e.io/v2/ReleaseRequest"],
        acts_for="urn:r5e:officer:privacy-1",
        role="privacy_officer",
        captured_at="2026-11-22T11:03:00Z",
        key_storage="hardware",
        hardware_attestation=b'{"device":"hsm-01","attested":true}',
    )


def endorse_person1(b: BundleBuilder, signer_kind: str = "personal", recovery_rule: dict[str, Any] | None = None) -> str:
    return b.endorse(
        subject_key=KEYS["person1"],
        kinds=["provenance.r5e.io/v2/Basis", "provenance.r5e.io/v2/BasisOverlay", "provenance.r5e.io/v2/Succession"],
        acts_for=PERSON_1_URI,
        role="subject",
        captured_at="2026-11-22T11:04:00Z",
        key_storage="personal_device",
        signer_kind=signer_kind,
        recovery_rule=recovery_rule,
    )


def build_all_cases() -> list[tuple[str, str, dict[str, Any], dict[str, Any], dict[str, Any]]]:
    cases: list[tuple[str, str, dict[str, Any], dict[str, Any], dict[str, Any]]] = []

    def register(
        name: str,
        description: str,
        builder: BundleBuilder,
        verdict: str,
        a11_findings: list[dict[str, Any]],
    ) -> None:
        bundle, case_meta = builder.build()
        case_meta = {"description": description, "name": name, **case_meta}
        report = {
            "amendment": "A11",
            "baselineClean": True,
            "expectedA11Findings": a11_findings,
            "format": "r5e.provenance-verify-report/v2",
            "verdict": verdict,
        }
        cases.append((name, description, bundle, case_meta, report))

    # =========================================================================
    # V1: basis_signatures (4 cases)
    # =========================================================================
    # 1. basis-person-two-signatures-valid
    b = BundleBuilder()
    endorse_person1(b, signer_kind="personal")
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    register(
        "basis-person-two-signatures-valid",
        "V1: Person Basis signed by both institution and personal key passes.",
        b,
        "ok",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check")],
    )

    # 2. basis-person-device-session-valid
    b = BundleBuilder()
    b.endorse(
        subject_key=KEYS["device_session"],
        kinds=["provenance.r5e.io/v2/Basis"],
        acts_for=PERSON_1_URI,
        role="subject",
        captured_at="2026-11-22T11:04:00Z",
        key_storage="personal_device",
        signer_kind="device_session",
    )
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["device_session"]])
    register(
        "basis-person-device-session-valid",
        "V1: Person Basis signed by institution and explicit device_session key passes.",
        b,
        "ok",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check")],
    )

    # 3. basis-person-one-signature-rejected
    b = BundleBuilder()
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"]])
    register(
        "basis-person-one-signature-rejected",
        "V1: Person Basis signed only by institution fails with basis_missing_counter_signature.",
        b,
        "failed",
        [
            make_finding(
                layer=2,
                subject=basis_ref,
                check="basis_signatures",
                result="failed",
                code="basis_missing_counter_signature",
                category="mechanical_check",
            )
        ],
    )

    # 4. basis-workload-no-person-valid
    b = BundleBuilder()
    basis_ref = b.add_basis(subjects=[], actor=WORKLOAD_URI, signers=[KEYS["institution"]])
    register(
        "basis-workload-no-person-valid",
        "V1: Machine workload Basis with empty subjects and one signature passes.",
        b,
        "ok",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check")],
    )

    # =========================================================================
    # V2: basis_declared_power (3 cases)
    # =========================================================================
    # 5. release-cites-declared-term-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        declared_terms=[
            {
                "enforceable": False,
                "scope": "external_sharing",
                "statement": "No external marketing disclosure.",
                "termId": "term-no-sharing",
            }
        ],
    )
    req_ref = b.add_release_request(basis_ref=basis_ref, ground_id="term-no-sharing")
    register(
        "release-cites-declared-term-rejected",
        "V2: ReleaseRequest citing a declaredTerms entry fails with act_cites_declared_or_absent_power.",
        b,
        "failed",
        [
            make_finding(
                layer=3,
                subject=req_ref,
                check="basis_declared_power",
                result="failed",
                code="act_cites_declared_or_absent_power",
                category="mechanical_check",
                about="term-no-sharing",
            )
        ],
    )

    # 6. release-cites-absent-power-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        powers=["capture", "keep"],
    )
    req_ref = b.add_release_request(basis_ref=basis_ref, ground_id="g-care", power="train_on")
    register(
        "release-cites-absent-power-rejected",
        "V2: ReleaseRequest citing a power absent from the ground fails with act_cites_declared_or_absent_power.",
        b,
        "failed",
        [
            make_finding(
                layer=3,
                subject=req_ref,
                check="basis_declared_power",
                result="failed",
                code="act_cites_declared_or_absent_power",
                category="mechanical_check",
                about="train_on",
            )
        ],
    )

    # 7. proposal-alone-authorises-nothing
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        powers=["capture", "keep"],
    )
    prop_ref = b.add_record(
        kind="BasisOverlay",
        stream=GOV_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:01:00Z",
        signers=[KEYS["institution"]],
        body={
            "basisRef": basis_ref,
            "effectiveAt": "2026-11-22T12:01:00Z",
            "overlayType": "amendment_proposal",
            "summary": "Propose adding disclose power",
        },
    )
    req_ref = b.add_release_request(basis_ref=prop_ref, ground_id="g-care", power="disclose")
    register(
        "proposal-alone-authorises-nothing",
        "V2: ReleaseRequest citing an unaccepted amendment_proposal overlay fails with proposal_authorises_nothing.",
        b,
        "failed",
        [
            make_finding(
                layer=3,
                subject=req_ref,
                check="basis_declared_power",
                result="failed",
                code="proposal_authorises_nothing",
                category="mechanical_check",
                about=prop_ref,
            )
        ],
    )

    # =========================================================================
    # V3: basis_overlay_order (2 cases)
    # =========================================================================
    # 8. release-after-withdrawal-overlay-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    wd_ref = b.add_record(
        kind="BasisOverlay",
        stream=GOV_STREAM,
        actor=PERSON_1_URI,
        captured_at="2026-11-22T12:05:00Z",
        signers=[KEYS["person1"]],
        body={
            "basisRef": basis_ref,
            "effectiveAt": "2026-11-22T12:05:00Z",
            "overlayType": "withdrawal",
            "summary": "Subject withdrew disclosure power",
        },
    )
    req_ref = b.add_release_request(basis_ref=basis_ref, captured_at="2026-11-22T12:10:00Z")
    register(
        "release-after-withdrawal-overlay-rejected",
        "V3: ReleaseRequest issued after a withdrawal BasisOverlay fails with basis_power_withdrawn_or_expired.",
        b,
        "failed",
        [
            make_finding(
                layer=3,
                subject=req_ref,
                check="basis_overlay_order",
                result="failed",
                code="basis_power_withdrawn_or_expired",
                category="mechanical_check",
                about=wd_ref,
            )
        ],
    )

    # 9. release-before-withdrawal-overlay-valid
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref, captured_at="2026-11-22T12:02:00Z")
    b.add_record(
        kind="BasisOverlay",
        stream=GOV_STREAM,
        actor=PERSON_1_URI,
        captured_at="2026-11-22T12:05:00Z",
        signers=[KEYS["person1"]],
        body={
            "basisRef": basis_ref,
            "effectiveAt": "2026-11-22T12:05:00Z",
            "overlayType": "withdrawal",
            "summary": "Subject withdrew disclosure power after earlier release",
        },
    )
    register(
        "release-before-withdrawal-overlay-valid",
        "V3: ReleaseRequest issued before a later withdrawal BasisOverlay passes.",
        b,
        "ok",
        [
            make_finding(
                layer=3,
                subject=req_ref,
                check="basis_overlay_order",
                result="ok",
                code="ok",
                category="mechanical_check",
                about=basis_ref,
            )
        ],
    )

    # =========================================================================
    # V4: release_request_approvals (5 cases)
    # =========================================================================
    # 10. release-approval-hardware-key-valid
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref, approver=KEYS["approver_hw"])
    register(
        "release-approval-hardware-key-valid",
        "V4: Hardware-backed attested approver key and complete subjects pass.",
        b,
        "ok",
        [
            make_finding(
                layer=2,
                subject=req_ref,
                check="release_request_approvals",
                result="ok",
                code="ok",
                category="cryptographic_proof",
                about=KEYS["approver_hw"].keyid,
            )
        ],
    )

    # 11. release-approval-administered-file-key-rejected
    b = BundleBuilder()
    b.endorse(
        subject_key=KEYS["approver_file"],
        kinds=["provenance.r5e.io/v2/ReleaseRequest"],
        acts_for="urn:r5e:officer:privacy-file",
        role="privacy_officer",
        captured_at="2026-11-22T11:03:00Z",
        key_storage="administered_device_file",
    )
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref, approver=KEYS["approver_file"])
    register(
        "release-approval-administered-file-key-rejected",
        "V4: Approver key with administered_device_file storage fails with approval_key_not_hardware.",
        b,
        "failed",
        [
            make_finding(
                layer=2,
                subject=req_ref,
                check="release_request_approvals",
                result="failed",
                code="approval_key_not_hardware",
                category="mechanical_check",
                about=KEYS["approver_file"].keyid,
            )
        ],
    )

    # 12. release-approval-signature-mismatch-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref, approver=KEYS["approver_hw"], tamper_sig=True)
    register(
        "release-approval-signature-mismatch-rejected",
        "V4: Corrupted approval signature fails with approval_signature_invalid.",
        b,
        "failed",
        [
            make_finding(
                layer=2,
                subject=req_ref,
                check="release_request_approvals",
                result="failed",
                code="approval_signature_invalid",
                category="cryptographic_proof",
                about=KEYS["approver_hw"].keyid,
            )
        ],
    )

    # 13. release-subjects-missing-person-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI, PERSON_2_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
    )
    req_ref = b.add_release_request(
        basis_ref=basis_ref,
        approver=KEYS["approver_hw"],
        subjects=[PERSON_1_URI],
    )
    register(
        "release-subjects-missing-person-rejected",
        "V4: ReleaseRequest omitting a subject governed by the Basis fails with release_subjects_incomplete.",
        b,
        "failed",
        [
            make_finding(
                layer=2,
                subject=req_ref,
                check="release_request_approvals",
                result="failed",
                code="release_subjects_incomplete",
                category="mechanical_check",
                about=PERSON_2_URI,
            )
        ],
    )

    # 14. release-workload-empty-subjects-valid
    b = BundleBuilder()
    endorse_hw_approver(b)
    basis_ref = b.add_basis(subjects=[], actor=WORKLOAD_URI, signers=[KEYS["institution"]])
    req_ref = b.add_release_request(
        basis_ref=basis_ref,
        approver=KEYS["approver_hw"],
        targets=[SESSION_W_URI],
        subjects=[],
    )
    register(
        "release-workload-empty-subjects-valid",
        "V4: Machine workload ReleaseRequest with empty subjects and valid hardware approval passes.",
        b,
        "ok",
        [
            make_finding(
                layer=2,
                subject=req_ref,
                check="release_request_approvals",
                result="ok",
                code="ok",
                category="cryptographic_proof",
                about=KEYS["approver_hw"].keyid,
            )
        ],
    )

    # =========================================================================
    # V5: witness_receipt_binding (3 cases)
    # =========================================================================
    # 15. witness-receipt-canonical-hash-valid
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref)
    fp = b.add_blob(b"released-encrypted-package-v1")
    rcpt_ref = b.add_release_receipt(
        request_ref=req_ref,
        outcome="released",
        released_fingerprint=fp,
        witness_receipt_ref=w_ref,
    )
    register(
        "witness-receipt-canonical-hash-valid",
        "V5: Pinned witness receipt matching canonical ReleaseRequest hash passes.",
        b,
        "ok",
        [
            make_finding(
                layer=3,
                subject=rcpt_ref,
                check="witness_receipt_binding",
                result="ok",
                code="ok",
                category="cryptographic_proof",
                about=w_ref,
            )
        ],
    )

    # 16. witness-receipt-hash-mismatch-rejected
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref, mismatch_hash=True)
    fp = b.add_blob(b"released-encrypted-package-v1")
    rcpt_ref = b.add_release_receipt(
        request_ref=req_ref,
        outcome="released",
        released_fingerprint=fp,
        witness_receipt_ref=w_ref,
    )
    register(
        "witness-receipt-hash-mismatch-rejected",
        "V5: Witness receipt with mismatched requestHash fails with witness_receipt_hash_mismatch.",
        b,
        "failed",
        [
            make_finding(
                layer=3,
                subject=rcpt_ref,
                check="witness_receipt_binding",
                result="failed",
                code="witness_receipt_hash_mismatch",
                category="cryptographic_proof",
                about=w_ref,
            )
        ],
    )

    # 17. witness-receipt-unpinned-witness-rejected
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref, witness_key=KEYS["rogue_witness"])
    fp = b.add_blob(b"released-encrypted-package-v1")
    rcpt_ref = b.add_release_receipt(
        request_ref=req_ref,
        outcome="released",
        released_fingerprint=fp,
        witness_receipt_ref=w_ref,
    )
    register(
        "witness-receipt-unpinned-witness-rejected",
        "V5: Witness receipt signed by unpinned witness key fails with witness_unpinned.",
        b,
        "failed",
        [
            make_finding(
                layer=3,
                subject=rcpt_ref,
                check="witness_receipt_binding",
                result="failed",
                code="witness_unpinned",
                category="cryptographic_proof",
                about=KEYS["rogue_witness"].keyid,
            )
        ],
    )

    # =========================================================================
    # V6: release_receipt_fingerprint (3 cases)
    # =========================================================================
    # 18. release-receipt-released-with-fingerprint-valid
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref)
    fp = b.add_blob(b"released-encrypted-package-v1")
    rcpt_ref = b.add_release_receipt(
        request_ref=req_ref,
        outcome="released",
        released_fingerprint=fp,
        witness_receipt_ref=w_ref,
    )
    register(
        "release-receipt-released-with-fingerprint-valid",
        "V6: ReleaseReceipt with outcome=released and releasedFingerprint passes.",
        b,
        "ok",
        [
            make_finding(
                layer=2,
                subject=rcpt_ref,
                check="release_receipt_fingerprint",
                result="ok",
                code="ok",
                category="mechanical_check",
                about=fp,
            )
        ],
    )

    # 19. release-receipt-released-missing-fingerprint-rejected
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref)
    rcpt_ref = b.add_release_receipt(
        request_ref=req_ref,
        outcome="released",
        released_fingerprint=None,
        witness_receipt_ref=w_ref,
    )
    register(
        "release-receipt-released-missing-fingerprint-rejected",
        "V6: ReleaseReceipt with outcome=released and missing releasedFingerprint fails.",
        b,
        "failed",
        [
            make_finding(
                layer=2,
                subject=rcpt_ref,
                check="release_receipt_fingerprint",
                result="failed",
                code="released_fingerprint_missing",
                category="mechanical_check",
            )
        ],
    )

    # 20. release-receipt-denied-without-fingerprint-valid
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref)
    rcpt_ref = b.add_release_receipt(
        request_ref=req_ref,
        outcome="denied",
        released_fingerprint=None,
        witness_receipt_ref=w_ref,
    )
    register(
        "release-receipt-denied-without-fingerprint-valid",
        "V6: ReleaseReceipt with outcome=denied and no releasedFingerprint passes.",
        b,
        "ok",
        [
            make_finding(
                layer=2,
                subject=rcpt_ref,
                check="release_receipt_fingerprint",
                result="ok",
                code="ok",
                category="mechanical_check",
            )
        ],
    )

    # =========================================================================
    # V7: succession_recovery (2 cases)
    # =========================================================================
    def add_recovery_succession(b: BundleBuilder, num_approvals: int) -> str:
        for rk in [KEYS["recovery_1"], KEYS["recovery_2"], KEYS["recovery_3"]]:
            b.add_key(rk)
        rule_ref = endorse_person1(
            b,
            recovery_rule={
                "recoveryKeys": [
                    KEYS["recovery_1"].keyid,
                    KEYS["recovery_2"].keyid,
                    KEYS["recovery_3"].keyid,
                ],
                "threshold": 2,
            },
        )
        msg = b"r5e-succession-recovery-v1\x00" + encode_canonical_json(
            {
                "newKey": KEYS["person1_new"].keyid,
                "oldKey": KEYS["person1"].keyid,
                "recoveryRuleRef": rule_ref,
            }
        )
        approvals = [
            {"signature": rk.sign(msg), "signerKey": rk.keyid}
            for rk in [KEYS["recovery_1"], KEYS["recovery_2"]][:num_approvals]
        ]
        return b.add_record(
            kind="Succession",
            stream=AUTH_STREAM,
            actor=PERSON_1_URI,
            captured_at="2026-11-22T12:06:00Z",
            signers=[KEYS["person1_new"]],
            schema_ref=A11_DEFS["provenance.r5e.io/v2/Succession"][0],
            body={
                "predecessor": KEYS["person1"].keyid,
                "reason": "Lost primary device key; recovered via registered recoveryRule",
                "recoveryProof": {
                    "approvals": approvals,
                    "recoveryRuleRef": rule_ref,
                },
                "successor": KEYS["person1_new"].keyid,
                "successorKey": KEYS["person1_new"].public_key_obj(),
            },
        )

    # 21. succession-recovery-threshold-met-valid
    b = BundleBuilder()
    succ_ref = add_recovery_succession(b, num_approvals=2)
    register(
        "succession-recovery-threshold-met-valid",
        "V7: Recovery-form Succession meeting recoveryRule.threshold (2-of-3) passes.",
        b,
        "ok",
        [
            make_finding(
                layer=2,
                subject=succ_ref,
                check="succession_recovery",
                result="ok",
                code="ok",
                category="cryptographic_proof",
            )
        ],
    )

    # 22. succession-recovery-threshold-short-rejected
    b = BundleBuilder()
    succ_ref = add_recovery_succession(b, num_approvals=1)
    register(
        "succession-recovery-threshold-short-rejected",
        "V7: Recovery-form Succession below recoveryRule.threshold (1-of-2) fails.",
        b,
        "failed",
        [
            make_finding(
                layer=2,
                subject=succ_ref,
                check="succession_recovery",
                result="failed",
                code="succession_recovery_threshold_not_met",
                category="cryptographic_proof",
            )
        ],
    )

    # =========================================================================
    # V8: erasure_l2_proof (4 cases)
    # =========================================================================
    def add_erasure_proof(b: BundleBuilder, copy_pairs: list[tuple[str, KeyPair]]) -> str:
        destroyed_at = "2026-11-22T12:10:00Z"
        confs = []
        for copy_id, kp in copy_pairs:
            b.add_key(kp)
            msg = b"r5e-erasure-proof-v1\x00" + encode_canonical_json(
                {"copyId": copy_id, "destroyedAt": destroyed_at, "session": SESSION_1_URI}
            )
            confs.append({"copyId": copy_id, "keyId": kp.keyid, "signature": kp.sign(msg)})
        proof_obj = {
            "copyConfirmations": confs,
            "destroyedAt": destroyed_at,
            "session": SESSION_1_URI,
        }
        return b.add_blob(encode_canonical_json(proof_obj))

    def add_erasure_answer(
        b: BundleBuilder,
        *,
        evidential_support: str,
        confirmed_copies: list[str],
        proof_ref: str | None = None,
    ) -> str:
        sess_entry: dict[str, Any] = {
            "backupState": {"status": "ciphertext_erased"},
            "confirmedCopies": confirmed_copies,
            "derivedItems": [],
            "evidentialSupport": evidential_support,
            "externalDisclosures": [],
            "governedState": "destroyed",
            "session": SESSION_1_URI,
            "trainingWithdrawalEffect": "Excluded from future training runs.",
        }
        if proof_ref is not None:
            sess_entry["proofRef"] = proof_ref
        return b.add_record(
            kind="ErasureAnswer",
            stream=GOV_STREAM,
            actor=INSTITUTION_URI,
            captured_at="2026-11-22T12:11:00Z",
            signers=[KEYS["institution"]],
            body={
                "discoveryBoundary": "Covers governed session store; excludes already-disclosed external copies.",
                "requestRef": "erasure-req-001",
                "sessions": [sess_entry],
                "subject": PERSON_1_URI,
            },
        )

    # 23. erasure-l2-all-copies-confirmed-valid
    b = BundleBuilder(custody_level=2, sealed_copies=["copy-a", "copy-b"])
    p_ref = add_erasure_proof(b, [("copy-a", KEYS["copy_a"]), ("copy-b", KEYS["copy_b"])])
    ea_ref = add_erasure_answer(
        b,
        evidential_support="sealed_key_service_proof",
        confirmed_copies=["copy-a", "copy-b"],
        proof_ref=p_ref,
    )
    register(
        "erasure-l2-all-copies-confirmed-valid",
        "V8: Level 2 ErasureAnswer with valid proofs from all sealedServiceCopies passes as cryptographic_proof.",
        b,
        "ok",
        [
            make_finding(
                layer=3,
                subject=ea_ref,
                check="erasure_l2_proof",
                result="ok",
                code="ok",
                category="cryptographic_proof",
                about=SESSION_1_URI,
            )
        ],
    )

    # 24. erasure-l2-partial-copies-confirmed-incomplete
    b = BundleBuilder(custody_level=2, sealed_copies=["copy-a", "copy-b"])
    p_ref = add_erasure_proof(b, [("copy-a", KEYS["copy_a"])])
    ea_ref = add_erasure_answer(
        b,
        evidential_support="sealed_key_service_proof",
        confirmed_copies=["copy-a"],
        proof_ref=p_ref,
    )
    register(
        "erasure-l2-partial-copies-confirmed-incomplete",
        "V8: Level 2 ErasureAnswer with valid proof for subset of sealedServiceCopies reports incomplete.",
        b,
        "incomplete",
        [
            make_finding(
                layer=3,
                subject=ea_ref,
                check="erasure_l2_proof",
                result="incomplete",
                code="erasure_copy_confirmation_pending",
                category="cryptographic_proof",
                about="copy-b",
            )
        ],
    )

    # 25. erasure-l2-unknown-copy-id-rejected
    b = BundleBuilder(custody_level=2, sealed_copies=["copy-a", "copy-b"])
    p_ref = add_erasure_proof(b, [("copy-a", KEYS["copy_a"]), ("copy-unknown", KEYS["copy_unknown"])])
    ea_ref = add_erasure_answer(
        b,
        evidential_support="sealed_key_service_proof",
        confirmed_copies=["copy-a", "copy-unknown"],
        proof_ref=p_ref,
    )
    register(
        "erasure-l2-unknown-copy-id-rejected",
        "V8: Level 2 ErasureAnswer listing a copy ID outside sealedServiceCopies fails.",
        b,
        "failed",
        [
            make_finding(
                layer=3,
                subject=ea_ref,
                check="erasure_l2_proof",
                result="failed",
                code="erasure_unknown_copy_id",
                category="cryptographic_proof",
                about="copy-unknown",
            )
        ],
    )

    # 26. erasure-l1-institution-claim-classified
    b = BundleBuilder(custody_level=1, sealed_copies=[])
    ea_ref = add_erasure_answer(
        b,
        evidential_support="institution_claim",
        confirmed_copies=[],
        proof_ref=None,
    )
    register(
        "erasure-l1-institution-claim-classified",
        "V8: Level 1 ErasureAnswer with institution_claim passes and is classified as institutional_assertion.",
        b,
        "ok",
        [
            make_finding(
                layer=3,
                subject=ea_ref,
                check="erasure_l2_proof",
                result="ok",
                code="ok",
                category="institutional_assertion",
                about=SESSION_1_URI,
            )
        ],
    )

    # =========================================================================
    # V9: salted_content_ref (3 cases)
    # =========================================================================
    salt_bytes = hashlib.sha256(b"r5e-a11-salted-test-salt-01").digest()
    plaintext = b"yes"
    s_ref = salted_ref(salt_bytes, plaintext)

    # 27. salted-content-carried-valid
    b = BundleBuilder()
    endorse_person1(b)
    b.salted_content[s_ref] = {"bytes": b64(plaintext), "salt": b64(salt_bytes)}
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        explanation_ref=s_ref,
    )
    register(
        "salted-content-carried-valid",
        "V9: Carried saltedContent (salt, bytes) matching bytes:sha256+salt:... passes as cryptographic_proof.",
        b,
        "ok",
        [
            make_finding(
                layer=1,
                subject=basis_ref,
                check="salted_content_ref",
                result="ok",
                code="ok",
                category="cryptographic_proof",
                about=s_ref,
            )
        ],
    )

    # 28. salted-content-digest-mismatch-rejected
    b = BundleBuilder()
    endorse_person1(b)
    b.salted_content[s_ref] = {"bytes": b64(b"no"), "salt": b64(salt_bytes)}
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        explanation_ref=s_ref,
    )
    register(
        "salted-content-digest-mismatch-rejected",
        "V9: Tampered saltedContent payload fails with salted_content_digest_mismatch.",
        b,
        "failed",
        [
            make_finding(
                layer=1,
                subject=basis_ref,
                check="salted_content_ref",
                result="failed",
                code="salted_content_digest_mismatch",
                category="cryptographic_proof",
                about=s_ref,
            )
        ],
    )

    # 29. salted-content-omitted-unavailable
    b = BundleBuilder()
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        explanation_ref=s_ref,
    )
    register(
        "salted-content-omitted-unavailable",
        "V9: Omitted saltedContent reports incomplete with unavailable_evidence.",
        b,
        "incomplete",
        [
            make_finding(
                layer=1,
                subject=basis_ref,
                check="salted_content_ref",
                result="incomplete",
                code="unavailable_evidence",
                category="unavailable_evidence",
                about=s_ref,
            )
        ],
    )

    # =========================================================================
    # V10: checkpoint_and_unlock_log (3 cases)
    # =========================================================================
    # 30. bundle-unrecorded-plaintext-flagged
    b = BundleBuilder(custody_level=1)
    payload_ref = b.add_blob(b"Sensitive session transcript plaintext")
    obs_ref = b.add_record(
        kind="Observation",
        stream=SESS_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:05:00Z",
        signers=[KEYS["institution"]],
        session=SESSION_1_URI,
        body={
            "contentRefs": [payload_ref],
            "topic": "user_message",
        },
    )
    register(
        "bundle-unrecorded-plaintext-flagged",
        "V10: Carried session plaintext payload without a matching Disclosure or ReleaseReceipt fails.",
        b,
        "failed",
        [
            make_finding(
                layer=3,
                subject=obs_ref,
                check="checkpoint_and_unlock_log",
                result="failed",
                code="unrecorded_plaintext_in_bundle",
                category="mechanical_check",
                about=payload_ref,
            )
        ],
    )

    # 31. l1-unlock-without-release-flagged
    b = BundleBuilder(custody_level=1)
    b.add_key(KEYS["operator"])
    b.unlock_log.append(
        {
            "entryId": "unlock-001",
            "operatorKey": KEYS["operator"].keyid,
            "releaseRef": None,
            "session": SESSION_1_URI,
            "unlockedAt": "2026-11-22T12:08:00Z",
        }
    )
    register(
        "l1-unlock-without-release-flagged",
        "V10: Level 1 key-service unlockLog entry lacking a matching release record fails.",
        b,
        "failed",
        [
            make_finding(
                layer=3,
                subject="unlock-001",
                check="checkpoint_and_unlock_log",
                result="failed",
                code="unlock_without_release_record",
                category="mechanical_check",
                about=SESSION_1_URI,
            )
        ],
    )

    # 32. checkpoint-forked-flagged
    b = BundleBuilder(custody_level=2)
    b.endorse(
        subject_key=KEYS["checkpoint"],
        kinds=["provenance.r5e.io/v2/Checkpoint"],
        acts_for=f"urn:r5e:node:{DEPLOYMENT_NAME}",
        role="checkpointer",
        captured_at="2026-11-22T11:02:30Z",
    )
    ckpt_ref = b.add_record(
        kind="Checkpoint",
        stream=CKPT_STREAM,
        actor=f"urn:r5e:node:{DEPLOYMENT_NAME}",
        captured_at="2026-11-22T12:09:00Z",
        signers=[KEYS["checkpoint"]],
        schema_ref=BASE_DEFS["provenance.r5e.io/v2/Checkpoint"][0],
        body={
            "seals": [b.chain_ref],
        },
    )
    b.checkpoints.append(ckpt_ref)
    pinned_ref = "evidence:sha256:" + ("a" * 64)
    b.pinned_checkpoints.append({"ref": pinned_ref, "seq": 1})
    register(
        "checkpoint-forked-flagged",
        "V10: Checkpoint at seq 1 diverging from pinnedCheckpoints fails with checkpoint_fork_or_stale.",
        b,
        "failed",
        [
            make_finding(
                layer=3,
                subject=ckpt_ref,
                check="checkpoint_and_unlock_log",
                result="failed",
                code="checkpoint_fork_or_stale",
                category="cryptographic_proof",
                about=pinned_ref,
            )
        ],
    )

    # =========================================================================
    # V11: definition_coexistence (1 case)
    # =========================================================================
    # 33. old-definition-record-still-verifies
    b = BundleBuilder(custody_level=2)
    old_end_ref = b.endorse(
        subject_key=KEYS["operator"],
        kinds=["provenance.r5e.io/v2/Observation"],
        acts_for="urn:r5e:operator:legacy-1",
        role="legacy_operator",
        captured_at="2026-11-22T11:05:00Z",
        use_baseline_schema=True,
    )
    endorse_hw_approver(b)
    register(
        "old-definition-record-still-verifies",
        "V11: Record citing a baseline schemaRef verifies alongside records citing the newer extended definition.",
        b,
        "ok",
        [
            make_finding(
                layer=1,
                subject=old_end_ref,
                check="definition_coexistence",
                result="ok",
                code="ok",
                category="mechanical_check",
                about=BASE_DEFS["provenance.r5e.io/v2/Endorsement"][0],
            )
        ],
    )

    return cases


def main() -> int:
    CASES_OUT_DIR.mkdir(parents=True, exist_ok=True)
    cases = build_all_cases()
    assert len(cases) == 33, f"Expected 33 cases, got {len(cases)}"

    for name, _desc, bundle, case_meta, report in cases:
        cdir = CASES_OUT_DIR / name
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / "bundle.json").write_text(
            json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (cdir / "case.json").write_text(
            json.dumps(case_meta, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (cdir / "expected-report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    print(f"Generated {len(cases)} A11 conformance test vector cases in {CASES_OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
