#!/usr/bin/env python3
"""Deterministic generator for Amendment A11 conformance test vectors (90 cases).

Generates `amendments/a11/cases/<case-name>/{bundle.json, case.json, expected-report.json}`
using deterministic Ed25519 keys, RFC 8785 / Core C1 canonical JSON, and valid DSSE envelopes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
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
SESS2_STREAM = f"urn:r5e:stream:{DEPLOYMENT_NAME}:session:02"
CKPT_STREAM = f"urn:r5e:stream:{DEPLOYMENT_NAME}:checkpoints"

INSTITUTION_URI = "urn:r5e:org:example-institution"
PERSON_1_URI = "urn:r5e:subject:person-1"
PERSON_2_URI = "urn:r5e:subject:person-2"
REPRESENTATIVE_URI = "urn:r5e:representative:guardian-1"
WORKLOAD_URI = "urn:r5e:workload:batch-1"
RECIPIENT_URI = "urn:r5e:recipient:auditor-1"
SESSION_1_URI = "urn:r5e:session:a11-0001"
SESSION_2_URI = "urn:r5e:session:a11-0002"
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


KEYS: dict[str, KeyPair] = {
    name: KeyPair.from_seed_name(name)
    for name in [
        "publisher",
        "bootstrap",
        "root",
        "hw_att_root",
        "institution",
        "institution_2",
        "person1",
        "person1_new",
        "person1_third",
        "person2",
        "representative",
        "device_session",
        "approver_hw",
        "approver_hw_2",
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
        "copy_c",
        "copy_unknown",
        "checkpoint",
        "operator",
        "attacker",
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

DEFAULT_SEALED_COPIES: list[tuple[str, KeyPair]] = [
    ("copy-a", KEYS["copy_a"]),
    ("copy-b", KEYS["copy_b"]),
]


def make_signed_hw_attestation(
    approver_key: KeyPair,
    *,
    root_key: KeyPair | None = None,
    device: str = "hsm-01",
    attested_at: str = "2026-11-22T11:02:30Z",
) -> bytes:
    rkey = root_key or KEYS["hw_att_root"]
    unsigned = {
        "attestedAt": attested_at,
        "device": device,
        "keyId": approver_key.keyid,
        "rootKeyId": rkey.keyid,
    }
    sig = rkey.sign(b"r5e-hw-attestation-v1\x00" + encode_canonical_json(unsigned))
    return encode_canonical_json({**unsigned, "signature": sig})


class BundleBuilder:
    """Helper for constructing valid canonical r5e.provenance-export/v2 bundles."""

    def __init__(
        self,
        custody_level: int = 2,
        sealed_copies: list[tuple[str, KeyPair]] | None = None,
        *,
        baseline_only: bool = False,
        approver_roles: list[dict[str, Any]] | None = None,
        recovery_keys: list[KeyPair] | None = None,
    ) -> None:
        self.custody_level = custody_level
        self.sealed_copies = (
            sealed_copies if sealed_copies is not None else list(DEFAULT_SEALED_COPIES)
        )
        self.baseline_only = baseline_only
        self.custom_approver_roles = approver_roles
        self.dep_recovery_keys = recovery_keys or []
        self.records: list[dict[str, Any]] = []
        self.blobs: dict[str, bytes] = {}
        self.keys: dict[str, KeyPair] = {}
        self.raw_key_overrides: dict[str, dict[str, str]] = {}
        self.stream_seq: dict[str, int] = {}
        self.stream_prev: dict[str, str] = {}
        self.checkpoints: list[str] = []
        self.salted_content: dict[str, dict[str, Any]] = {}
        self.witness_receipts: dict[str, dict[str, Any]] = {}
        self.unlock_log: list[Any] = []
        self.pinned_checkpoints: list[Any] = []
        self.extra_top_fields: dict[str, Any] = {}
        self.trusted_profiles: list[str] = []
        self.trusted_checkpoints: list[dict[str, Any]] | None = None
        self.chain_ref: str | None = None
        self.opened_sessions: set[str] = set()

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
            "schemas": {
                k: schemas[k]
                for k in sorted(schemas.keys())
                if k.startswith("provenance.r5e.io/v2/")
            },
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
            KEYS["checkpoint"],
        ]:
            self.add_key(kp)
        if not self.baseline_only:
            for kp in [KEYS["hw_att_root"], KEYS["witness"], KEYS["overseer"]]:
                self.add_key(kp)
            for _, ckp in self.sealed_copies:
                self.add_key(ckp)

        for _, raw in BASE_DEFS.values():
            self.add_blob(raw)
        if not self.baseline_only:
            for _, raw in A11_DEFS.values():
                self.add_blob(raw)

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

        all_op_keys = sorted(
            {
                KEYS["bootstrap"].keyid,
                KEYS["root"].keyid,
                KEYS["institution"].keyid,
                KEYS["institution_2"].keyid,
                KEYS["person1"].keyid,
                KEYS["person1_new"].keyid,
                KEYS["person1_third"].keyid,
                KEYS["person2"].keyid,
                KEYS["representative"].keyid,
                KEYS["device_session"].keyid,
                KEYS["approver_hw"].keyid,
                KEYS["approver_hw_2"].keyid,
                KEYS["approver_file"].keyid,
                KEYS["checkpoint"].keyid,
                KEYS["operator"].keyid,
                KEYS["recovery_1"].keyid,
            }
        )
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
        if self.baseline_only:
            self.op_profile_ref = self.base_op_profile_ref
        else:
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
                    {"definition": ref, "kind": kind}
                    for kind, (ref, _) in sorted(BASE_DEFS.items())
                ]
            },
        )
        if not self.baseline_only:
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
                        {"definition": ref, "kind": kind}
                        for kind, (ref, _) in sorted(A11_DEFS.items())
                    ]
                },
            )

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
                    {"definition": ref, "kind": kind}
                    for kind, (ref, _) in sorted(BASE_DEFS.items())
                ],
                "deployment": DEPLOYMENT_NAME,
                "publication": pub_base_ref,
                "publisher": KEYS["publisher"].keyid,
            },
        )

        if self.baseline_only:
            dep_body: dict[str, Any] = {
                "accepts": cs_ref,
                "bootstrap": KEYS["bootstrap"].keyid,
                "claimedBy": KEYS["root"].keyid,
                "roots": [
                    {
                        "key": KEYS["root"].keyid,
                        "publicKey": KEYS["root"].public_key_obj(),
                    }
                ],
                "threshold": 1,
            }
            dep_schema = BASE_DEFS["provenance.r5e.io/v2/Deployment"][0]
        else:
            roles = (
                self.custom_approver_roles
                if self.custom_approver_roles is not None
                else [
                    {
                        "keys": [
                            KEYS["approver_hw"].keyid,
                            KEYS["approver_hw_2"].keyid,
                            KEYS["approver_file"].keyid,
                        ],
                        "role": "privacy_officer",
                    }
                ]
            )
            dep_body = {
                "accepts": cs_ref,
                "approverRoles": roles,
                "bootstrap": KEYS["bootstrap"].keyid,
                "claimedBy": KEYS["root"].keyid,
                "custodyLevel": self.custody_level,
                "hardwareAttestationRoots": [KEYS["hw_att_root"].keyid],
                "overseerKey": KEYS["overseer"].keyid,
                "roots": [
                    {
                        "key": KEYS["root"].keyid,
                        "publicKey": KEYS["root"].public_key_obj(),
                    }
                ],
                "sealedServiceCopies": [
                    {"copyId": cid, "keyId": ckp.keyid} for cid, ckp in self.sealed_copies
                ],
                "threshold": 1,
                "witnessKeys": [KEYS["witness"].keyid],
            }
            if self.dep_recovery_keys:
                dep_body["recoveryKeys"] = [rk.keyid for rk in self.dep_recovery_keys]
            dep_schema = A11_DEFS["provenance.r5e.io/v2/Deployment"][0]

        self.chain_ref = self.add_record(
            kind="Deployment",
            stream=START_STREAM,
            actor=f"urn:r5e:node:{DEPLOYMENT_NAME}",
            captured_at="2026-11-22T11:01:05Z",
            signers=[KEYS["bootstrap"], KEYS["root"]],
            profile_ref=self.op_profile_ref,
            schema_ref=dep_schema,
            body=dep_body,
        )

        inst_kinds = (
            [
                "provenance.r5e.io/v2/Observation",
                "provenance.r5e.io/v2/Disclosure",
                "provenance.r5e.io/v2/SessionOpened",
                "provenance.r5e.io/v2/SessionClosed",
            ]
            if self.baseline_only
            else [
                "provenance.r5e.io/v2/Basis",
                "provenance.r5e.io/v2/BasisOverlay",
                "provenance.r5e.io/v2/ReleaseRequest",
                "provenance.r5e.io/v2/ReleaseReceipt",
                "provenance.r5e.io/v2/ErasureAnswer",
                "provenance.r5e.io/v2/Observation",
                "provenance.r5e.io/v2/Disclosure",
                "provenance.r5e.io/v2/RetentionHold",
                "provenance.r5e.io/v2/RetentionHoldRelease",
                "provenance.r5e.io/v2/SessionOpened",
                "provenance.r5e.io/v2/SessionClosed",
                "provenance.r5e.io/v2/Succession",
            ]
        )
        self.endorse(
            subject_key=KEYS["institution"],
            kinds=inst_kinds,
            acts_for=INSTITUTION_URI,
            role="institution_recorder",
            captured_at="2026-11-22T11:02:00Z",
            use_baseline_schema=self.baseline_only,
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
        prev_override: str | None = None,
        corrupt_sig_index: int | None = None,
    ) -> str:
        for kp in signers:
            self.add_key(kp)

        seq = seq_override if seq_override is not None else self.stream_seq.get(stream, 0) + 1
        prev = prev_override if seq_override is not None else self.stream_prev.get(stream)
        if seq_override is None:
            self.stream_seq[stream] = seq

        full_kind = f"provenance.r5e.io/v2/{kind}"
        s_ref = schema_ref or (
            BASE_DEFS[full_kind][0] if self.baseline_only else MERGED_SCHEMAS[full_kind]
        )
        p_ref = profile_ref or self.op_profile_ref

        payload: dict[str, Any] = {
            "actor": actor,
            "apiVersion": "provenance.r5e.io/v2",
            "body": body,
            "capturedAt": captured_at,
            "issuer": signers[0].keyid,
            "kind": kind,
            "previous": prev,
            "profileRef": p_ref,
            "schemaRef": s_ref,
            "seq": seq,
            "stream": stream,
        }
        if session is not None:
            payload["session"] = session
        if causes:
            payload["causes"] = sorted(set(causes))

        payload_bytes = encode_canonical_json(payload)
        rec_ref = "evidence:sha256:" + sha256_hex(payload_bytes)
        pae = dsse_pae(PAYLOAD_TYPE, payload_bytes)
        sigs = []
        for idx, kp in enumerate(signers):
            sig_val = kp.sign(pae if idx != corrupt_sig_index else pae + b"-corrupt")
            sigs.append({"keyid": kp.keyid, "sig": sig_val})

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
        hardware_attestation_ref: str | None = None,
        signer_kind: str | None = None,
        recovery_rule: dict[str, Any] | None = None,
        not_before: str = "2026-11-01T00:00:00Z",
        not_after: str = "2027-11-22T00:00:00Z",
        use_baseline_schema: bool = False,
    ) -> str:
        self.add_key(subject_key)
        body: dict[str, Any] = {
            "actsFor": acts_for,
            "kinds": sorted(set(kinds)),
            "mayEndorse": False,
            "notAfter": not_after,
            "notBefore": not_before,
            "role": role,
            "subject": subject_key.keyid,
        }
        if key_storage is not None:
            body["keyStorage"] = key_storage
        if hardware_attestation_ref is not None:
            body["hardwareAttestationRef"] = hardware_attestation_ref
        elif hardware_attestation is not None:
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

    def add_session_opened(
        self,
        *,
        session: str = SESSION_1_URI,
        stream: str = SESS_STREAM,
        basis_refs: list[str] | None = None,
        captured_at: str = "2026-11-22T12:00:30Z",
    ) -> str:
        self.opened_sessions.add(session)
        body: dict[str, Any] = {"session": session}
        if basis_refs:
            body["contextRefs"] = sorted(set(basis_refs))
        return self.add_record(
            kind="SessionOpened",
            stream=stream,
            actor=INSTITUTION_URI,
            captured_at=captured_at,
            signers=[KEYS["institution"]],
            session=session,
            body=body,
        )

    def add_basis(
        self,
        *,
        subjects: list[str],
        signers: list[KeyPair],
        actor: str = PERSON_1_URI,
        representative: str | None = None,
        powers: list[str] | None = None,
        ground_id: str = "g-care",
        declared_terms: list[dict[str, Any]] | None = None,
        explanation_ref: str | None = None,
        captured_at: str = "2026-11-22T12:00:00Z",
        until: str | None = "2027-11-22T00:00:00Z",
        until_event: str | None = None,
        approval_roles: list[str] | None = None,
        threshold: int = 1,
        session: str | None = None,
        corrupt_sig_index: int | None = None,
    ) -> str:
        exp_ref = explanation_ref or self.add_blob(b"Plain-language governance explanation v1.")
        pwr_list = powers if powers is not None else ["capture", "keep", "disclose"]
        dur = {"untilEvent": until_event} if until_event is not None else {"until": until}
        roles = approval_roles if approval_roles is not None else ["privacy_officer"]
        body: dict[str, Any] = {
            "actor": actor,
            "explanationRef": exp_ref,
            "grounds": [
                {
                    "groundId": ground_id,
                    "instrument": "institutional-custody-policy-v1",
                    "powers": [
                        {
                            "approvalRule": {"roles": roles, "threshold": threshold},
                            "duration": dur,
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
        if representative is not None:
            body["representative"] = representative
        if declared_terms is not None:
            body["declaredTerms"] = declared_terms

        return self.add_record(
            kind="Basis",
            stream=GOV_STREAM,
            actor=actor,
            captured_at=captured_at,
            signers=signers,
            session=session,
            body=body,
            corrupt_sig_index=corrupt_sig_index,
        )

    def sign_release_approval(
        self,
        *,
        approver: KeyPair,
        request_id: str,
        recipient_key: str,
        basis_ref: str,
        contract_version: str,
        role: str = "privacy_officer",
        tamper: bool = False,
        signer_key_override: str | None = None,
    ) -> dict[str, str]:
        self.add_key(approver)
        msg_obj = {
            "basisFingerprint": basis_ref,
            "contractVersion": contract_version if not tamper else contract_version + "-tampered",
            "recipientKey": recipient_key,
            "requestId": request_id,
        }
        sig = approver.sign(b"r5e-release-approval-v1\x00" + encode_canonical_json(msg_obj))
        return {
            "role": role,
            "signature": sig,
            "signerKey": signer_key_override or approver.keyid,
        }

    def add_release_request(
        self,
        *,
        basis_ref: str,
        ground_id: str = "g-care",
        power: str = "disclose",
        targets: list[str] | None = None,
        subjects: list[str] | None = None,
        approver: KeyPair | None = None,
        approvals: list[dict[str, str]] | None = None,
        role: str = "privacy_officer",
        tamper_sig: bool = False,
        captured_at: str = "2026-11-22T12:02:00Z",
        request_id: str = "req-a11-0123456789abcdef0123456789abcdef",
        contract_version: str | None = None,
        auto_open_session: bool = True,
        not_before: str = "2026-11-22T12:00:00Z",
        not_after: str = "2026-11-23T00:00:00Z",
    ) -> str:
        self.add_key(KEYS["recipient"])
        tgt_list = targets if targets is not None else [SESSION_1_URI]
        if auto_open_session:
            for t in tgt_list:
                if t.startswith("urn:r5e:session:") and t not in self.opened_sessions:
                    stream = SESS_STREAM if t == SESSION_1_URI else SESS2_STREAM
                    brefs = [basis_ref] if basis_ref.startswith("evidence:sha256:") else []
                    self.add_session_opened(
                        session=t, stream=stream, basis_refs=brefs, captured_at="2026-11-22T12:00:30Z"
                    )

        app_key = approver or KEYS["approver_hw"]
        cver = contract_version or self.chain_ref or "v1"
        app_list = (
            approvals
            if approvals is not None
            else [
                self.sign_release_approval(
                    approver=app_key,
                    request_id=request_id,
                    recipient_key=KEYS["recipient"].keyid,
                    basis_ref=basis_ref,
                    contract_version=cver,
                    role=role,
                    tamper=tamper_sig,
                )
            ]
        )
        body: dict[str, Any] = {
            "approvals": app_list,
            "basisRef": basis_ref,
            "contractVersion": cver,
            "groundId": ground_id,
            "power": power,
            "reason": "Authorized audit disclosure",
            "recipient": RECIPIENT_URI,
            "recipientKey": KEYS["recipient"].keyid,
            "requestId": request_id,
            "sealed": False,
            "subjects": subjects if subjects is not None else [PERSON_1_URI],
            "targets": tgt_list,
            "timeWindow": {
                "notAfter": not_after,
                "notBefore": not_before,
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
        add_to_blobs: bool = True,
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
        receipt_ref = bytes_ref(receipt_bytes)
        if add_to_blobs:
            self.blobs[receipt_ref] = receipt_bytes
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
        key_entries = []
        for kid, kp in sorted(self.keys.items()):
            if kid in self.raw_key_overrides:
                key_entries.append(self.raw_key_overrides[kid])
            else:
                key_entries.append(kp.bundle_entry())

        bundle: dict[str, Any] = {
            "blobs": [
                {"base64": b64(raw), "ref": ref} for ref, raw in sorted(self.blobs.items())
            ],
            "checkpoints": self.checkpoints,
            "format": "r5e.provenance-export/v2",
            "keys": key_entries,
            "omissions": [],
            "proofs": [],
            "publicationProofs": [],
            "records": self.records,
            "scope": {
                "at": [
                    {"event": self.stream_prev[s], "seq": self.stream_seq[s], "stream": s}
                    for s in sorted(self.stream_seq.keys())
                ],
                "query": {"amendment": "baseline"} if self.baseline_only else {"amendment": "A11"},
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
        for k, v in self.extra_top_fields.items():
            bundle[k] = v

        case_meta: dict[str, Any] = {
            "minStartSeq": None,
            "trustedChain": self.chain_ref,
            "trustedProfiles": self.trusted_profiles,
            "trustedPublishers": [KEYS["publisher"].keyid],
            "trustedRoots": None,
        }
        if self.trusted_checkpoints is not None:
            case_meta["trustedCheckpoints"] = self.trusted_checkpoints
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


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (
            f["layer"],
            f["subject"],
            f["check"],
            f["code"],
            "" if f["about"] is None else f["about"],
        ),
    )


def endorse_hw_approver(
    b: BundleBuilder,
    *,
    key: KeyPair | None = None,
    role: str = "privacy_officer",
    signed_attestation: bool = True,
    not_before: str = "2026-11-01T00:00:00Z",
    not_after: str = "2027-11-22T00:00:00Z",
    captured_at: str = "2026-11-22T11:03:00Z",
) -> str:
    kp = key or KEYS["approver_hw"]
    att = (
        make_signed_hw_attestation(kp)
        if signed_attestation
        else b'{"device":"hsm-01","attested":true}'
    )
    return b.endorse(
        subject_key=kp,
        kinds=["provenance.r5e.io/v2/ReleaseRequest"],
        acts_for="urn:r5e:officer:privacy-1",
        role=role,
        captured_at=captured_at,
        key_storage="hardware",
        hardware_attestation=att,
        not_before=not_before,
        not_after=not_after,
    )


def endorse_person1(
    b: BundleBuilder,
    signer_kind: str = "personal",
    recovery_rule: dict[str, Any] | None = None,
    captured_at: str = "2026-11-22T11:04:00Z",
) -> str:
    return b.endorse(
        subject_key=KEYS["person1"],
        kinds=[
            "provenance.r5e.io/v2/Basis",
            "provenance.r5e.io/v2/BasisOverlay",
            "provenance.r5e.io/v2/Succession",
        ],
        acts_for=PERSON_1_URI,
        role="subject",
        captured_at=captured_at,
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
        *,
        baseline_clean: bool = True,
        mode: str | None = None,
    ) -> None:
        bundle, case_meta = builder.build()
        case_meta = {"description": description, "name": name, **case_meta}
        if mode is not None:
            case_meta["mode"] = mode
        report = {
            "amendment": "A11",
            "baselineClean": baseline_clean,
            "expectedA11Findings": sort_findings(a11_findings),
            "format": "r5e.provenance-verify-report/v2",
            "verdict": verdict,
        }
        cases.append((name, description, bundle, case_meta, report))

    def add_erasure_proof(
        b: BundleBuilder,
        copy_pairs: list[tuple[str, KeyPair]],
        *,
        tamper_index: int | None = None,
        duplicate_copy: tuple[str, KeyPair] | None = None,
    ) -> str:
        destroyed_at = "2026-11-22T12:10:00Z"
        confs = []
        for idx, (copy_id, kp) in enumerate(copy_pairs):
            b.add_key(kp)
            msg = b"r5e-erasure-proof-v1\x00" + encode_canonical_json(
                {
                    "copyId": copy_id,
                    "destroyedAt": destroyed_at if idx != tamper_index else "2026-11-22T12:10:01Z",
                    "session": SESSION_1_URI,
                }
            )
            confs.append({"copyId": copy_id, "keyId": kp.keyid, "signature": kp.sign(msg)})
        if duplicate_copy is not None:
            dup_id, dup_kp = duplicate_copy
            b.add_key(dup_kp)
            confs.append(
                {
                    "copyId": dup_id,
                    "keyId": dup_kp.keyid,
                    "signature": dup_kp.sign(b"bad-duplicate-confirmation"),
                }
            )
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
        governed_state: str = "destroyed",
        preservation_grounds: list[dict[str, Any]] | None = None,
    ) -> str:
        sess_entry: dict[str, Any] = {
            "backupState": {"status": "ciphertext_erased"},
            "confirmedCopies": confirmed_copies,
            "derivedItems": [],
            "evidentialSupport": evidential_support,
            "externalDisclosures": [],
            "governedState": governed_state,
            "session": SESSION_1_URI,
            "trainingWithdrawalEffect": "Excluded from future training runs.",
        }
        if proof_ref is not None:
            sess_entry["proofRef"] = proof_ref
        if preservation_grounds is not None:
            sess_entry["preservationGrounds"] = preservation_grounds
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

    def add_recovery_succession(
        b: BundleBuilder,
        num_approvals: int,
        *,
        recovery_keys: list[KeyPair] | None = None,
        approval_keys: list[KeyPair] | None = None,
        threshold: int = 2,
    ) -> str:
        rkeys = recovery_keys or [KEYS["recovery_1"], KEYS["recovery_2"], KEYS["recovery_3"]]
        for rk in rkeys:
            b.add_key(rk)
        rule_ref = endorse_person1(
            b,
            recovery_rule={
                "recoveryKeys": [rk.keyid for rk in rkeys],
                "threshold": threshold,
            },
        )
        msg = b"r5e-succession-recovery-v1\x00" + encode_canonical_json(
            {
                "newKey": KEYS["person1_new"].keyid,
                "oldKey": KEYS["person1"].keyid,
                "recoveryRuleRef": rule_ref,
            }
        )
        sign_with = approval_keys if approval_keys is not None else rkeys[:num_approvals]
        approvals = [{"signature": rk.sign(msg), "signerKey": rk.keyid} for rk in sign_with]
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

    # =========================================================================
    # CORE 33 CASES (V1–V11)
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
        "V1: Person Basis signed by institution and explicit device_session key passes as institutional_assertion.",
        b,
        "ok",
        [
            make_finding(
                layer=2,
                subject=basis_ref,
                check="basis_signatures",
                result="ok",
                code="basis_person_signed_by_device_session",
                category="institutional_assertion",
            )
        ],
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="failed", code="act_cites_declared_or_absent_power", category="mechanical_check", about="term-no-sharing"),
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="failed", code="act_cites_declared_or_absent_power", category="mechanical_check", about="train_on"),
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
    b.add_session_opened(session=SESSION_1_URI, basis_refs=[basis_ref])
    req_ref = b.add_release_request(basis_ref=prop_ref, ground_id="g-care", power="disclose", auto_open_session=False)
    register(
        "proposal-alone-authorises-nothing",
        "V2: ReleaseRequest citing an unaccepted amendment_proposal overlay fails with proposal_authorises_nothing.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="failed", code="proposal_authorises_nothing", category="mechanical_check", about=prop_ref),
        ],
    )

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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="failed", code="basis_power_withdrawn_or_expired", category="mechanical_check", about=wd_ref),
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 10. release-approval-hardware-key-valid
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref, approver=KEYS["approver_hw"])
    register(
        "release-approval-hardware-key-valid",
        "V4: Hardware-backed cryptographically attested approver key and complete subjects pass.",
        b,
        "ok",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="failed", code="approval_key_not_hardware", category="mechanical_check", about=KEYS["approver_file"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="failed", code="approval_signature_invalid", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="failed", code="release_subjects_incomplete", category="mechanical_check", about=PERSON_2_URI),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 15. witness-receipt-canonical-hash-valid
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref, add_to_blobs=False)
    fp = bytes_ref(b"released-encrypted-package-v1")
    rcpt_ref = b.add_release_receipt(
        request_ref=req_ref,
        outcome="released",
        released_fingerprint=fp,
        witness_receipt_ref=w_ref,
    )
    register(
        "witness-receipt-canonical-hash-valid",
        "V5: Pinned witness receipt matching canonical ReleaseRequest hash passes (and external releasedFingerprint/witnessReceiptRef stay baseline-clean).",
        b,
        "ok",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="ok", code="ok", category="mechanical_check", about=fp),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=rcpt_ref, check="witness_receipt_binding", result="ok", code="ok", category="cryptographic_proof", about=w_ref),
        ],
    )

    # 16. witness-receipt-hash-mismatch-rejected
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref, mismatch_hash=True, add_to_blobs=False)
    fp = bytes_ref(b"released-encrypted-package-v1")
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="ok", code="ok", category="mechanical_check", about=fp),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=rcpt_ref, check="witness_receipt_binding", result="failed", code="witness_receipt_hash_mismatch", category="cryptographic_proof", about=w_ref),
        ],
    )

    # 17. witness-receipt-unpinned-witness-rejected
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref, witness_key=KEYS["rogue_witness"], add_to_blobs=False)
    fp = bytes_ref(b"released-encrypted-package-v1")
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="ok", code="ok", category="mechanical_check", about=fp),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=rcpt_ref, check="witness_receipt_binding", result="failed", code="witness_unpinned", category="cryptographic_proof", about=KEYS["rogue_witness"].keyid),
        ],
    )

    # 18. release-receipt-released-with-fingerprint-valid
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref, add_to_blobs=False)
    fp = bytes_ref(b"released-encrypted-package-v1")
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="ok", code="ok", category="mechanical_check", about=fp),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=rcpt_ref, check="witness_receipt_binding", result="ok", code="ok", category="cryptographic_proof", about=w_ref),
        ],
    )

    # 19. release-receipt-released-missing-fingerprint-rejected
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref, add_to_blobs=False)
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="failed", code="released_fingerprint_missing", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=rcpt_ref, check="witness_receipt_binding", result="ok", code="ok", category="cryptographic_proof", about=w_ref),
        ],
        baseline_clean=False,
    )

    # 20. release-receipt-denied-without-fingerprint-valid
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref, add_to_blobs=False)
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
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=rcpt_ref, check="witness_receipt_binding", result="ok", code="ok", category="cryptographic_proof", about=w_ref),
        ],
    )

    # 21. succession-recovery-threshold-met-valid
    b = BundleBuilder()
    succ_ref = add_recovery_succession(b, num_approvals=2)
    register(
        "succession-recovery-threshold-met-valid",
        "V7: Recovery-form Succession meeting recoveryRule.threshold (2-of-3) passes.",
        b,
        "ok",
        [make_finding(layer=2, subject=succ_ref, check="succession_recovery", result="ok", code="ok", category="cryptographic_proof")],
    )

    # 22. succession-recovery-threshold-short-rejected
    b = BundleBuilder()
    succ_ref = add_recovery_succession(b, num_approvals=1)
    register(
        "succession-recovery-threshold-short-rejected",
        "V7: Recovery-form Succession below recoveryRule.threshold (1-of-2) fails.",
        b,
        "failed",
        [make_finding(layer=2, subject=succ_ref, check="succession_recovery", result="failed", code="succession_recovery_threshold_not_met", category="cryptographic_proof")],
    )

    # 23. erasure-l2-all-copies-confirmed-valid
    b = BundleBuilder(custody_level=2)
    p_ref = add_erasure_proof(b, [("copy-a", KEYS["copy_a"]), ("copy-b", KEYS["copy_b"])])
    ea_ref = add_erasure_answer(
        b,
        evidential_support="sealed_key_service_proof",
        confirmed_copies=["copy-a", "copy-b"],
        proof_ref=p_ref,
    )
    register(
        "erasure-l2-all-copies-confirmed-valid",
        "V8: Level 2 ErasureAnswer with valid proofs from all pinned sealedServiceCopies passes as cryptographic_proof.",
        b,
        "ok",
        [make_finding(layer=3, subject=ea_ref, check="erasure_l2_proof", result="ok", code="ok", category="cryptographic_proof", about=SESSION_1_URI)],
    )

    # 24. erasure-l2-partial-copies-confirmed-incomplete
    b = BundleBuilder(custody_level=2)
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
        [make_finding(layer=3, subject=ea_ref, check="erasure_l2_proof", result="incomplete", code="erasure_copy_confirmation_pending", category="unavailable_evidence", about="copy-b")],
    )

    # 25. erasure-l2-unknown-copy-id-rejected
    b = BundleBuilder(custody_level=2)
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
            make_finding(layer=3, subject=ea_ref, check="erasure_l2_proof", result="failed", code="erasure_unknown_copy_id", category="cryptographic_proof", about="copy-unknown"),
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
        [make_finding(layer=3, subject=ea_ref, check="erasure_l2_proof", result="ok", code="ok", category="institutional_assertion", about=SESSION_1_URI)],
    )

    # 27. salted-content-carried-valid
    salt_bytes = hashlib.sha256(b"r5e-a11-salted-test-salt-01").digest()
    plaintext = b"yes"
    s_ref = salted_ref(salt_bytes, plaintext)

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
            make_finding(layer=1, subject=basis_ref, check="salted_content_ref", result="ok", code="ok", category="cryptographic_proof", about=s_ref),
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
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
            make_finding(layer=1, subject=basis_ref, check="salted_content_ref", result="failed", code="salted_content_digest_mismatch", category="cryptographic_proof", about=s_ref),
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
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
        "V9: Omitted saltedContent reports incomplete with salted_content_omitted.",
        b,
        "incomplete",
        [
            make_finding(layer=1, subject=basis_ref, check="salted_content_ref", result="incomplete", code="salted_content_omitted", category="unavailable_evidence", about=s_ref),
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
        ],
    )

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
        body={"contentRefs": [payload_ref], "topic": "user_message"},
    )
    register(
        "bundle-unrecorded-plaintext-flagged",
        "V10: Carried session plaintext payload without a matching Disclosure or ReleaseReceipt fails.",
        b,
        "failed",
        [make_finding(layer=3, subject=obs_ref, check="checkpoint_and_unlock_log", result="failed", code="unrecorded_plaintext_in_bundle", category="mechanical_check", about=payload_ref)],
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
        [make_finding(layer=3, subject="unlock-001", check="checkpoint_and_unlock_log", result="failed", code="unlock_without_release_record", category="mechanical_check", about=SESSION_1_URI)],
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
        body={"seals": [b.chain_ref]},
    )
    b.checkpoints.append(ckpt_ref)
    pinned_ref = "evidence:sha256:" + ("a" * 64)
    b.pinned_checkpoints.append({"ref": pinned_ref, "seq": 1})
    register(
        "checkpoint-forked-flagged",
        "V10: Checkpoint at seq 1 diverging from pinnedCheckpoints fails with checkpoint_fork_or_stale.",
        b,
        "failed",
        [make_finding(layer=3, subject=ckpt_ref, check="checkpoint_and_unlock_log", result="failed", code="checkpoint_fork_or_stale", category="cryptographic_proof", about=pinned_ref)],
    )

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

    # =========================================================================
    # ADVERSARIAL REGRESSION CASES (57 cases)
    # =========================================================================

    # 34. baseline-bundle-under-a11-entry-ok
    b = BundleBuilder(baseline_only=True)
    blob_ref = b.add_blob(b"Pre-A11 baseline session payload")
    b.add_record(
        kind="Observation",
        stream=SESS_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:05:00Z",
        signers=[KEYS["institution"]],
        session=SESSION_1_URI,
        body={"contentRefs": [blob_ref], "topic": "baseline_note"},
    )
    register(
        "baseline-bundle-under-a11-entry-ok",
        "Entry-point compatibility: unchanged pre-A11 baseline bundle with carried session blob verifies ok.",
        b,
        "ok",
        [],
        mode="baseline",
    )

    # 35. baseline-export-rejects-unexpected-a11-top-keys
    b = BundleBuilder(baseline_only=True)
    b.extra_top_fields["unlockLog"] = []
    register(
        "baseline-export-rejects-unexpected-a11-top-keys",
        "Baseline export validation rejects stray A11 top-level keys with malformed_bundle.",
        b,
        "failed",
        [],
        baseline_clean=False,
        mode="baseline",
    )

    # 36. baseline-incomplete-propagates-to-a11-verdict
    b = BundleBuilder()
    endorse_person1(b)
    omitted_blob_ref = bytes_ref(b"omitted-explanation-not-in-blobs")
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        explanation_ref=omitted_blob_ref,
    )
    register(
        "baseline-incomplete-propagates-to-a11-verdict",
        "Baseline incomplete finding (omitted explanation blob) propagates to overall A11 verdict=incomplete.",
        b,
        "incomplete",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check")],
        baseline_clean=False,
    )

    # 37. release-request-malformed-target-uri-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    b.add_release_request(
        basis_ref=basis_ref,
        targets=["mailto:alice@example.org"],
        auto_open_session=False,
    )
    register(
        "release-request-malformed-target-uri-rejected",
        "Schema boundary: ReleaseRequest target URI outside evidence:sha256 or urn:r5e:session fails body validation.",
        b,
        "failed",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check")],
        baseline_clean=False,
    )

    # 38. release-request-low-entropy-id-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    b.add_release_request(basis_ref=basis_ref, request_id="short-id")
    register(
        "release-request-low-entropy-id-rejected",
        "Schema boundary: ReleaseRequest requestId shorter than 22 chars fails body validation.",
        b,
        "failed",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check")],
        baseline_clean=False,
    )

    # 39. erasure-kept-missing-preservation-grounds-rejected
    b = BundleBuilder(custody_level=2)
    add_erasure_answer(
        b,
        evidential_support="sealed_key_service_proof",
        confirmed_copies=[],
        governed_state="kept",
        preservation_grounds=None,
    )
    register(
        "erasure-kept-missing-preservation-grounds-rejected",
        "Schema boundary: ErasureAnswer with governedState=kept omitting preservationGrounds fails body validation.",
        b,
        "failed",
        [],
        baseline_clean=False,
    )

    # 40. salted-content-on-disclosure-and-endorsement-valid
    b = BundleBuilder(custody_level=1)
    att_salt = hashlib.sha256(b"r5e-a11-att-salt-01").digest()
    att_bytes = make_signed_hw_attestation(KEYS["approver_hw"])
    att_sref = salted_ref(att_salt, att_bytes)
    b.salted_content[att_sref] = {"bytes": b64(att_bytes), "salt": b64(att_salt)}
    end_ref = b.endorse(
        subject_key=KEYS["approver_hw"],
        kinds=["provenance.r5e.io/v2/ReleaseRequest"],
        acts_for="urn:r5e:officer:privacy-1",
        role="privacy_officer",
        captured_at="2026-11-22T11:03:00Z",
        key_storage="hardware",
        hardware_attestation_ref=att_sref,
    )
    disc_salt = hashlib.sha256(b"r5e-a11-disc-salt-01").digest()
    disc_plain = b"disclosed-item-salted"
    disc_sref = salted_ref(disc_salt, disc_plain)
    b.salted_content[disc_sref] = {"bytes": b64(disc_plain), "salt": b64(disc_salt)}
    disc_ref = b.add_record(
        kind="Disclosure",
        stream=GOV_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:04:00Z",
        signers=[KEYS["institution"]],
        body={
            "outcome": "provided",
            "providedRefs": [disc_sref],
            "reason": "Salted disclosure reference check",
            "recipient": RECIPIENT_URI,
            "requestedRefs": [disc_sref],
        },
    )
    register(
        "salted-content-on-disclosure-and-endorsement-valid",
        "Salted content references accepted on Endorsement.hardwareAttestationRef and Disclosure.providedRefs.",
        b,
        "ok",
        [
            make_finding(layer=1, subject=disc_ref, check="salted_content_ref", result="ok", code="ok", category="cryptographic_proof", about=disc_sref),
            make_finding(layer=1, subject=end_ref, check="salted_content_ref", result="ok", code="ok", category="cryptographic_proof", about=att_sref),
        ],
    )

    # 41. a11-timestamp-non-utc-offset-rejected
    b = BundleBuilder()
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    b.add_record(
        kind="BasisOverlay",
        stream=GOV_STREAM,
        actor=PERSON_1_URI,
        captured_at="2026-11-22T12:05:00Z",
        signers=[KEYS["person1"]],
        body={
            "basisRef": basis_ref,
            "effectiveAt": "2026-11-22T12:05:00+01:00",
            "overlayType": "withdrawal",
            "summary": "Non-UTC offset timestamp must fail schema validation",
        },
    )
    register(
        "a11-timestamp-non-utc-offset-rejected",
        "Schema boundary: non-UTC offset (+01:00) on A11 timestamp field effectiveAt fails body validation.",
        b,
        "failed",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check")],
        baseline_clean=False,
    )

    # 42. retention-hold-missing-review-at-rejected
    b = BundleBuilder()
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        powers=["capture", "keep", "hold"],
    )
    b.add_session_opened(session=SESSION_1_URI, basis_refs=[basis_ref])
    hold_ref = b.add_record(
        kind="RetentionHold",
        stream=GOV_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:03:00Z",
        signers=[KEYS["institution"]],
        body={
            "basisRef": basis_ref,
            "reason": "Litigation hold missing reviewAt",
            "scope": SESSION_1_URI,
        },
    )
    register(
        "retention-hold-missing-review-at-rejected",
        "V2: RetentionHold citing basisRef without reviewAt fails with retention_hold_missing_review_at.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=3, subject=hold_ref, check="basis_declared_power", result="failed", code="retention_hold_missing_review_at", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=hold_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 43. erasure-empty-copy-id-rejected
    b = BundleBuilder(custody_level=2)
    add_erasure_answer(
        b,
        evidential_support="sealed_key_service_proof",
        confirmed_copies=[""],
        proof_ref=bytes_ref(b"{}"),
    )
    register(
        "erasure-empty-copy-id-rejected",
        "Schema boundary: empty string in confirmedCopies fails body validation.",
        b,
        "failed",
        [],
        baseline_clean=False,
    )

    # 44. basis-person-two-institutional-signers-rejected
    b = BundleBuilder()
    b.endorse(
        subject_key=KEYS["institution_2"],
        kinds=["provenance.r5e.io/v2/Basis"],
        acts_for=INSTITUTION_URI,
        role="institution_backup",
        captured_at="2026-11-22T11:02:30Z",
    )
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["institution_2"]],
    )
    register(
        "basis-person-two-institutional-signers-rejected",
        "V1: Person Basis signed by two institutional keys fails with basis_invalid_signer_binding.",
        b,
        "failed",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="failed", code="basis_invalid_signer_binding", category="mechanical_check")],
    )

    # 45. basis-person-unendorsed-device-session-rejected
    b = BundleBuilder()
    b.endorse(
        subject_key=KEYS["person1"],
        kinds=["provenance.r5e.io/v2/Basis"],
        acts_for=PERSON_1_URI,
        role="subject",
        captured_at="2026-11-22T11:04:00Z",
        key_storage="personal_device",
        signer_kind=None,
    )
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    register(
        "basis-person-unendorsed-device-session-rejected",
        "V1: Person Basis whose second signer endorsement lacks signerKind personal/device_session fails.",
        b,
        "failed",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="failed", code="basis_invalid_signer_binding", category="mechanical_check")],
    )

    # 46. basis-person-representative-one-signature-rejected
    b = BundleBuilder()
    basis_ref = b.add_basis(
        subjects=[],
        representative=REPRESENTATIVE_URI,
        actor=WORKLOAD_URI,
        signers=[KEYS["institution"]],
    )
    register(
        "basis-person-representative-one-signature-rejected",
        "V1: Basis with empty subjects but non-empty representative requires 2 signatures.",
        b,
        "failed",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="failed", code="basis_missing_counter_signature", category="mechanical_check")],
    )

    # 47. basis-person-invalid-second-signature-rejected
    b = BundleBuilder()
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        corrupt_sig_index=1,
    )
    register(
        "basis-person-invalid-second-signature-rejected",
        "V1: 2-signer person Basis with corrupted second DSSE signature fails in both baseline and V1.",
        b,
        "failed",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="failed", code="basis_missing_counter_signature", category="mechanical_check")],
        baseline_clean=False,
    )

    # 48. basis-person-three-signers-rejected
    b = BundleBuilder()
    endorse_person1(b)
    b.endorse(
        subject_key=KEYS["institution_2"],
        kinds=["provenance.r5e.io/v2/Basis"],
        acts_for=INSTITUTION_URI,
        role="institution_backup",
        captured_at="2026-11-22T11:02:30Z",
    )
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"], KEYS["institution_2"]],
    )
    register(
        "basis-person-three-signers-rejected",
        "V1: Person Basis with 3 signers fails with basis_unexpected_signature_count.",
        b,
        "failed",
        [make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="failed", code="basis_unexpected_signature_count", category="mechanical_check")],
        baseline_clean=False,
    )

    # 49. workload-basis-cited-for-session-naming-person-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    person_basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    workload_basis_ref = b.add_basis(subjects=[], actor=WORKLOAD_URI, signers=[KEYS["institution"]])
    b.add_session_opened(session=SESSION_1_URI, basis_refs=[person_basis_ref])
    req_ref = b.add_release_request(
        basis_ref=workload_basis_ref,
        targets=[SESSION_1_URI],
        subjects=[PERSON_1_URI],
        auto_open_session=False,
    )
    register(
        "workload-basis-cited-for-session-naming-person-rejected",
        "V2: One-signature workload Basis (subjects=[]) cited to release a session naming a person fails with basis_subjects_do_not_cover_targets.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=person_basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=workload_basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="failed", code="basis_subjects_do_not_cover_targets", category="mechanical_check", about=PERSON_1_URI),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=workload_basis_ref),
        ],
    )

    # 50. release-missing-basis-incomplete
    b = BundleBuilder()
    endorse_hw_approver(b)
    missing_basis = "evidence:sha256:" + ("0" * 64)
    b.add_session_opened(session=SESSION_W_URI, basis_refs=[])
    req_ref = b.add_release_request(
        basis_ref=missing_basis,
        targets=[SESSION_W_URI],
        subjects=[],
        auto_open_session=False,
    )
    register(
        "release-missing-basis-incomplete",
        "V2/V4: ReleaseRequest citing uncarried basisRef yields incomplete (basis_ref_missing), never ok.",
        b,
        "incomplete",
        [
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="incomplete", code="basis_ref_missing", category="unavailable_evidence", about=missing_basis),
        ],
    )

    # 51. release-wrong-kind-basis-rejected
    b = BundleBuilder()
    end_ref = endorse_hw_approver(b)
    b.add_session_opened(session=SESSION_W_URI, basis_refs=[])
    req_ref = b.add_release_request(
        basis_ref=end_ref,
        targets=[SESSION_W_URI],
        subjects=[],
        auto_open_session=False,
    )
    register(
        "release-wrong-kind-basis-rejected",
        "V2: ReleaseRequest citing a non-Basis record (Endorsement) fails with basis_ref_wrong_kind.",
        b,
        "failed",
        [
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="failed", code="basis_ref_wrong_kind", category="mechanical_check", about=end_ref),
        ],
    )

    # 52. retention-hold-absent-hold-power-rejected
    b = BundleBuilder()
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        powers=["capture", "keep"],
    )
    b.add_session_opened(session=SESSION_1_URI, basis_refs=[basis_ref])
    hold_ref = b.add_record(
        kind="RetentionHold",
        stream=GOV_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:03:00Z",
        signers=[KEYS["institution"]],
        body={
            "basisRef": basis_ref,
            "reason": "Hold without hold power",
            "reviewAt": "2027-01-01T00:00:00Z",
            "scope": SESSION_1_URI,
        },
    )
    register(
        "retention-hold-absent-hold-power-rejected",
        "V2: RetentionHold citing a Basis without hold power fails with act_cites_declared_or_absent_power.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=3, subject=hold_ref, check="basis_declared_power", result="failed", code="act_cites_declared_or_absent_power", category="mechanical_check", about="hold"),
            make_finding(layer=3, subject=hold_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 53. disclosure-unauthorized-basis-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        powers=["capture", "keep"],
    )
    req_ref = b.add_release_request(basis_ref=basis_ref, power="disclose")
    disc_ref = b.add_record(
        kind="Disclosure",
        stream=GOV_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:04:00Z",
        signers=[KEYS["institution"]],
        body={
            "excluding": [],
            "outcome": "provided",
            "reason": "Disclosure linked to unauthorized ReleaseRequest",
            "recipient": RECIPIENT_URI,
            "releaseRequestRef": req_ref,
            "scope": SESSION_1_URI,
        },
    )
    register(
        "disclosure-unauthorized-basis-rejected",
        "V2: Disclosure linked via releaseRequestRef to Basis lacking disclose power fails V2.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=3, subject=disc_ref, check="basis_declared_power", result="failed", code="act_cites_declared_or_absent_power", category="mechanical_check", about="disclose"),
            make_finding(layer=3, subject=disc_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="failed", code="act_cites_declared_or_absent_power", category="mechanical_check", about="disclose"),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 54. release-absent-power-and-withdrawn-both-reported
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        powers=["capture", "keep"],
    )
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
            "summary": "Withdrawn before absent-power release",
        },
    )
    req_ref = b.add_release_request(
        basis_ref=basis_ref, power="train_on", captured_at="2026-11-22T12:10:00Z"
    )
    register(
        "release-absent-power-and-withdrawn-both-reported",
        "V2 + V3: Both absent-power (V2) and post-withdrawal (V3) findings are emitted independently.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="failed", code="act_cites_declared_or_absent_power", category="mechanical_check", about="train_on"),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="failed", code="basis_power_withdrawn_or_expired", category="mechanical_check", about=wd_ref),
        ],
    )

    # 55. basis-duration-until-expired-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        until="2026-11-22T12:05:00Z",
    )
    req_ref = b.add_release_request(
        basis_ref=basis_ref,
        captured_at="2026-11-22T12:05:00.000000001Z",
        not_before="2026-11-22T12:05:00Z",
        not_after="2026-11-22T12:06:00Z",
    )
    register(
        "basis-duration-until-expired-rejected",
        "V3: ReleaseRequest past Basis duration.until (nanosecond precision) fails with basis_power_withdrawn_or_expired.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="failed", code="basis_power_withdrawn_or_expired", category="mechanical_check", about=basis_ref),
        ],
    )

    # 56. basis-duration-until-event-triggered-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        until=None,
        until_event="session_closed",
    )
    open_ref = b.add_session_opened(session=SESSION_1_URI, basis_refs=[basis_ref])
    close_ref = b.add_record(
        kind="SessionClosed",
        stream=SESS_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:01:30Z",
        signers=[KEYS["institution"]],
        session=SESSION_1_URI,
        body={
            "outcome": "completed",
            "reason": "Session completed",
            "session": SESSION_1_URI,
            "through": [{"event": open_ref, "seq": 1, "stream": SESS_STREAM}],
        },
    )
    req_ref = b.add_release_request(
        basis_ref=basis_ref, captured_at="2026-11-22T12:02:00Z", auto_open_session=False
    )
    register(
        "basis-duration-until-event-triggered-rejected",
        "V3: ReleaseRequest after carried SessionClosed matching duration.untilEvent fails with basis_power_withdrawn_or_expired.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="failed", code="basis_power_withdrawn_or_expired", category="mechanical_check", about=close_ref),
        ],
    )

    # 57. basis-duration-until-event-unverified-incomplete
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        until=None,
        until_event="case_closed_externally",
    )
    req_ref = b.add_release_request(basis_ref=basis_ref, captured_at="2026-11-22T12:02:00Z")
    register(
        "basis-duration-until-event-unverified-incomplete",
        "V3: Basis with unresolvable duration.untilEvent reports incomplete (until_event_unverified).",
        b,
        "incomplete",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="incomplete", code="until_event_unverified", category="unavailable_evidence", about="case_closed_externally"),
        ],
    )

    # 58. basis-withdrawal-earlier-seq-backdated-request-rejected
    b = BundleBuilder(custody_level=1)
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
            "summary": "Earlier stream seq withdrawal",
        },
    )
    req_ref = b.add_release_request(
        basis_ref=basis_ref, captured_at="2026-11-22T12:04:00Z"
    )
    register(
        "basis-withdrawal-earlier-seq-backdated-request-rejected",
        "V3: Same-stream earlier seq withdrawal cannot be bypassed by backdating a later ReleaseRequest.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="failed", code="basis_power_withdrawn_or_expired", category="mechanical_check", about=wd_ref),
        ],
    )

    # 59. basis-overlay-l2-witness-order-rejected
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref, captured_at="2026-11-22T12:02:00Z")
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
            "summary": "Withdrawal witnessed at logIndex 0 before release at logIndex 1",
        },
    )
    w_wd = b.add_witness_receipt(request_ref=wd_ref, log_index=0, logged_at="2026-11-22T12:02:01Z", add_to_blobs=False)
    w_req = b.add_witness_receipt(request_ref=req_ref, log_index=1, logged_at="2026-11-22T12:02:05Z", add_to_blobs=False)
    fp = bytes_ref(b"released-l2-order-test")
    rcpt_ref = b.add_release_receipt(
        request_ref=req_ref, outcome="released", released_fingerprint=fp, witness_receipt_ref=w_req
    )
    register(
        "basis-overlay-l2-witness-order-rejected",
        "V3: At Level 2, witness logIndex ordering places withdrawal (logIndex 0) before release (logIndex 1).",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="ok", code="ok", category="mechanical_check", about=fp),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="failed", code="basis_power_withdrawn_or_expired", category="mechanical_check", about=wd_ref),
            make_finding(layer=3, subject=rcpt_ref, check="witness_receipt_binding", result="ok", code="ok", category="cryptographic_proof", about=w_req),
            make_finding(layer=3, subject=w_wd, check="witness_receipt_binding", result="ok", code="ok", category="cryptographic_proof", about=w_wd),
        ],
    )

    # 60. release-subjects-missing-target-person-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    b.endorse(
        subject_key=KEYS["person2"],
        kinds=["provenance.r5e.io/v2/Basis"],
        acts_for=PERSON_2_URI,
        role="subject",
        captured_at="2026-11-22T11:04:30Z",
        key_storage="personal_device",
        signer_kind="personal",
    )
    basis_p1 = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    basis_p2 = b.add_basis(
        subjects=[PERSON_2_URI], actor=PERSON_2_URI, signers=[KEYS["institution"], KEYS["person2"]]
    )
    b.add_session_opened(session=SESSION_1_URI, basis_refs=[basis_p1, basis_p2])
    req_ref = b.add_release_request(
        basis_ref=basis_p1,
        targets=[SESSION_1_URI],
        subjects=[PERSON_1_URI],
        auto_open_session=False,
    )
    register(
        "release-subjects-missing-target-person-rejected",
        "V4: ReleaseRequest omitting a second person governed by the targeted session fails with release_subjects_incomplete.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_p1, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=basis_p2, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="failed", code="release_subjects_incomplete", category="mechanical_check", about=PERSON_2_URI),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="failed", code="basis_subjects_do_not_cover_targets", category="mechanical_check", about=PERSON_2_URI),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_p1),
        ],
    )

    # 61. release-subjects-unresolved-target-incomplete
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(
        basis_ref=basis_ref,
        targets=[SESSION_2_URI],
        subjects=[PERSON_1_URI],
        auto_open_session=False,
    )
    register(
        "release-subjects-unresolved-target-incomplete",
        "V4: ReleaseRequest referencing an uncarried target session reports incomplete (release_target_missing).",
        b,
        "incomplete",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="incomplete", code="release_target_missing", category="unavailable_evidence", about=SESSION_2_URI),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 62. release-approval-unsigned-hardware-attestation-incomplete
    b = BundleBuilder()
    endorse_hw_approver(b, signed_attestation=False)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref, approver=KEYS["approver_hw"])
    register(
        "release-approval-unsigned-hardware-attestation-incomplete",
        "V4: Unsigned hardwareAttestationRef JSON yields incomplete (hardware_attestation_unverified, institutional_assertion).",
        b,
        "incomplete",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="incomplete", code="hardware_attestation_unverified", category="institutional_assertion", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 63. release-approval-revoked-endorsement-rejected
    b = BundleBuilder()
    hw_end_ref = endorse_hw_approver(b)
    b.add_record(
        kind="Revocation",
        stream=AUTH_STREAM,
        actor=f"urn:r5e:root:{DEPLOYMENT_NAME}",
        captured_at="2026-11-22T11:30:00Z",
        signers=[KEYS["root"]],
        schema_ref=BASE_DEFS["provenance.r5e.io/v2/Revocation"][0],
        body={"reason": "Approver key compromised", "target": hw_end_ref},
    )
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref, approver=KEYS["approver_hw"])
    register(
        "release-approval-revoked-endorsement-rejected",
        "V4: Hardware approver whose Endorsement was revoked prior to request fails with approval_endorsement_inactive.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="failed", code="approval_endorsement_inactive", category="mechanical_check", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 64. release-approval-expired-endorsement-rejected
    b = BundleBuilder()
    endorse_hw_approver(b, not_after="2026-11-22T11:59:59Z")
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref, approver=KEYS["approver_hw"])
    register(
        "release-approval-expired-endorsement-rejected",
        "V4: Hardware approver whose Endorsement expired prior to request fails with approval_endorsement_inactive.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="failed", code="approval_endorsement_inactive", category="mechanical_check", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 65. release-approval-role-not-in-contract-rejected
    b = BundleBuilder()
    endorse_hw_approver(b, role="unlisted_role")
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        approval_roles=["unlisted_role"],
    )
    req_ref = b.add_release_request(
        basis_ref=basis_ref, approver=KEYS["approver_hw"], role="unlisted_role"
    )
    register(
        "release-approval-role-not-in-contract-rejected",
        "V4: Approver role absent from Deployment.approverRoles fails closed with approval_role_unlisted.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="failed", code="approval_role_unlisted", category="mechanical_check", about="unlisted_role"),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 66. release-approval-duplicate-key-second-role-valid
    b = BundleBuilder(
        approver_roles=[
            {"keys": [KEYS["approver_hw"].keyid], "role": "observer"},
            {"keys": [KEYS["approver_hw"].keyid], "role": "privacy_officer"},
        ]
    )
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    rid = "req-a11-duprole-0123456789abcdef01234567"
    app1 = b.sign_release_approval(
        approver=KEYS["approver_hw"],
        request_id=rid,
        recipient_key=KEYS["recipient"].keyid,
        basis_ref=basis_ref,
        contract_version=b.chain_ref or "v1",
        role="observer",
    )
    app2 = b.sign_release_approval(
        approver=KEYS["approver_hw"],
        request_id=rid,
        recipient_key=KEYS["recipient"].keyid,
        basis_ref=basis_ref,
        contract_version=b.chain_ref or "v1",
        role="privacy_officer",
    )
    req_ref = b.add_release_request(
        basis_ref=basis_ref, request_id=rid, approvals=[app1, app2]
    )
    register(
        "release-approval-duplicate-key-second-role-valid",
        "V4: Same key listed under non-qualifying role then qualifying role deduplicates by (signerKey, role) and passes.",
        b,
        "ok",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 67. witness-receipt-standalone-mismatched-hash-rejected
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref, mismatch_hash=True, add_to_blobs=False)
    register(
        "witness-receipt-standalone-mismatched-hash-rejected",
        "V5: Standalone witnessReceipts entry with wrong requestHash fails even without a ReleaseReceipt.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=w_ref, check="witness_receipt_binding", result="failed", code="witness_receipt_hash_mismatch", category="cryptographic_proof", about=w_ref),
        ],
    )

    # 68. witness-receipt-wrong-kind-request-rejected
    b = BundleBuilder(custody_level=2)
    end_ref = endorse_hw_approver(b)
    w_ref = b.add_witness_receipt(request_ref=end_ref, add_to_blobs=False)
    register(
        "witness-receipt-wrong-kind-request-rejected",
        "V5: Witness receipt whose requestRef points to a non-ReleaseRequest (Endorsement) fails with witness_request_wrong_kind.",
        b,
        "failed",
        [
            make_finding(layer=3, subject=w_ref, check="witness_receipt_binding", result="failed", code="witness_request_wrong_kind", category="cryptographic_proof", about=end_ref),
        ],
    )

    # 69. release-receipt-denied-with-fingerprint-rejected
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    w_ref = b.add_witness_receipt(request_ref=req_ref, add_to_blobs=False)
    fp = bytes_ref(b"unexpected-fingerprint-on-denied")
    rcpt_ref = b.add_release_receipt(
        request_ref=req_ref,
        outcome="denied",
        released_fingerprint=fp,
        witness_receipt_ref=w_ref,
    )
    register(
        "release-receipt-denied-with-fingerprint-rejected",
        "V6: ReleaseReceipt with outcome=denied carrying releasedFingerprint fails with released_fingerprint_unexpected.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="failed", code="released_fingerprint_unexpected", category="mechanical_check", about=fp),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=rcpt_ref, check="witness_receipt_binding", result="ok", code="ok", category="cryptographic_proof", about=w_ref),
        ],
    )

    # 70. release-receipt-l2-missing-both-fingerprint-and-witness-rejected
    b = BundleBuilder(custody_level=2)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref)
    rcpt_ref = b.add_release_receipt(
        request_ref=req_ref,
        outcome="released",
        released_fingerprint=None,
        witness_receipt_ref=None,
    )
    register(
        "release-receipt-l2-missing-both-fingerprint-and-witness-rejected",
        "V6: L2 released ReleaseReceipt omitting both releasedFingerprint and witnessReceiptRef emits both V6 findings without short-circuiting.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="failed", code="released_fingerprint_missing", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="failed", code="witness_receipt_missing_l2", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
        baseline_clean=False,
    )

    # 71. succession-recovery-institution-only-rejected
    b = BundleBuilder()
    succ_ref = add_recovery_succession(
        b,
        num_approvals=1,
        recovery_keys=[KEYS["root"], KEYS["recovery_1"]],
        approval_keys=[KEYS["root"]],
        threshold=1,
    )
    register(
        "succession-recovery-institution-only-rejected",
        "V7: Recovery Succession satisfied solely by excluded institutional/root key fails with succession_institution_only_rejected.",
        b,
        "failed",
        [make_finding(layer=2, subject=succ_ref, check="succession_recovery", result="failed", code="succession_institution_only_rejected", category="cryptographic_proof")],
    )

    # 72. succession-recovery-rule-from-prior-succession-valid
    b = BundleBuilder()
    for rk in [KEYS["recovery_1"], KEYS["recovery_2"], KEYS["recovery_3"]]:
        b.add_key(rk)
    endorse_person1(b)
    first_succ_ref = b.add_record(
        kind="Succession",
        stream=AUTH_STREAM,
        actor=PERSON_1_URI,
        captured_at="2026-11-22T12:05:00Z",
        signers=[KEYS["person1"], KEYS["person1_new"]],
        schema_ref=A11_DEFS["provenance.r5e.io/v2/Succession"][0],
        body={
            "predecessor": KEYS["person1"].keyid,
            "reason": "Standard rotation setting new recoveryRule",
            "recoveryRule": {
                "recoveryKeys": [KEYS["recovery_1"].keyid, KEYS["recovery_2"].keyid],
                "threshold": 1,
            },
            "successor": KEYS["person1_new"].keyid,
            "successorKey": KEYS["person1_new"].public_key_obj(),
        },
    )
    msg2 = b"r5e-succession-recovery-v1\x00" + encode_canonical_json(
        {
            "newKey": KEYS["person1_third"].keyid,
            "oldKey": KEYS["person1_new"].keyid,
            "recoveryRuleRef": first_succ_ref,
        }
    )
    second_succ_ref = b.add_record(
        kind="Succession",
        stream=AUTH_STREAM,
        actor=PERSON_1_URI,
        captured_at="2026-11-22T12:06:00Z",
        signers=[KEYS["person1_third"]],
        schema_ref=A11_DEFS["provenance.r5e.io/v2/Succession"][0],
        body={
            "predecessor": KEYS["person1_new"].keyid,
            "reason": "Recovered using recoveryRule from prior valid Succession",
            "recoveryProof": {
                "approvals": [{"signature": KEYS["recovery_1"].sign(msg2), "signerKey": KEYS["recovery_1"].keyid}],
                "recoveryRuleRef": first_succ_ref,
            },
            "successor": KEYS["person1_third"].keyid,
            "successorKey": KEYS["person1_third"].public_key_obj(),
        },
    )
    register(
        "succession-recovery-rule-from-prior-succession-valid",
        "V7: Recovery Succession citing recoveryRule updated on a prior valid Succession passes.",
        b,
        "ok",
        [
            make_finding(layer=2, subject=first_succ_ref, check="succession_recovery", result="ok", code="ok", category="cryptographic_proof"),
            make_finding(layer=2, subject=second_succ_ref, check="succession_recovery", result="ok", code="ok", category="cryptographic_proof"),
        ],
    )

    # 73. succession-standard-a11-unrelated-signers-rejected
    b = BundleBuilder()
    endorse_person1(b)
    succ_ref = b.add_record(
        kind="Succession",
        stream=AUTH_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:06:00Z",
        signers=[KEYS["institution"], KEYS["root"]],
        schema_ref=A11_DEFS["provenance.r5e.io/v2/Succession"][0],
        body={
            "predecessor": KEYS["person1"].keyid,
            "reason": "Forged standard succession signed by institution and root",
            "successor": KEYS["person1_new"].keyid,
            "successorKey": KEYS["person1_new"].public_key_obj(),
        },
    )
    register(
        "succession-standard-a11-unrelated-signers-rejected",
        "V7: Standard-form A11 Succession signed by unrelated keys fails with succession_signer_mismatch.",
        b,
        "failed",
        [make_finding(layer=2, subject=succ_ref, check="succession_recovery", result="failed", code="succession_signer_mismatch", category="cryptographic_proof")],
    )

    # 74. succession-recovery-cross-subject-rule-rejected
    b = BundleBuilder()
    for rk in [KEYS["recovery_1"], KEYS["recovery_2"]]:
        b.add_key(rk)
    endorse_person1(b)
    other_rule_ref = b.endorse(
        subject_key=KEYS["person2"],
        kinds=["provenance.r5e.io/v2/Succession"],
        acts_for=PERSON_2_URI,
        role="subject",
        captured_at="2026-11-22T11:04:30Z",
        key_storage="personal_device",
        signer_kind="personal",
        recovery_rule={"recoveryKeys": [KEYS["recovery_1"].keyid], "threshold": 1},
    )
    msg = b"r5e-succession-recovery-v1\x00" + encode_canonical_json(
        {
            "newKey": KEYS["person1_new"].keyid,
            "oldKey": KEYS["person1"].keyid,
            "recoveryRuleRef": other_rule_ref,
        }
    )
    succ_ref = b.add_record(
        kind="Succession",
        stream=AUTH_STREAM,
        actor=PERSON_1_URI,
        captured_at="2026-11-22T12:06:00Z",
        signers=[KEYS["person1_new"]],
        schema_ref=A11_DEFS["provenance.r5e.io/v2/Succession"][0],
        body={
            "predecessor": KEYS["person1"].keyid,
            "reason": "Cross-subject recovery rule hijack attempt",
            "recoveryProof": {
                "approvals": [{"signature": KEYS["recovery_1"].sign(msg), "signerKey": KEYS["recovery_1"].keyid}],
                "recoveryRuleRef": other_rule_ref,
            },
            "successor": KEYS["person1_new"].keyid,
            "successorKey": KEYS["person1_new"].public_key_obj(),
        },
    )
    register(
        "succession-recovery-cross-subject-rule-rejected",
        "V7: Recovery Succession citing another person's Endorsement.recoveryRule fails with succession_recovery_rule_unknown.",
        b,
        "failed",
        [make_finding(layer=2, subject=succ_ref, check="succession_recovery", result="failed", code="succession_recovery_rule_unknown", category="cryptographic_proof", about=other_rule_ref)],
    )

    # 75. erasure-l2-unendorsed-copy-key-rejected
    b = BundleBuilder(custody_level=2)
    p_ref = add_erasure_proof(b, [("copy-a", KEYS["attacker"]), ("copy-b", KEYS["copy_b"])])
    ea_ref = add_erasure_answer(
        b,
        evidential_support="sealed_key_service_proof",
        confirmed_copies=["copy-a", "copy-b"],
        proof_ref=p_ref,
    )
    register(
        "erasure-l2-unendorsed-copy-key-rejected",
        "V8: Destruction proof signed by throwaway key instead of copy-a's pinned keyId fails.",
        b,
        "failed",
        [make_finding(layer=3, subject=ea_ref, check="erasure_l2_proof", result="failed", code="erasure_proof_invalid_or_missing_l2", category="cryptographic_proof", about="copy-a")],
    )

    # 76. erasure-l2-empty-copies-vacuous-rejected
    b = BundleBuilder(custody_level=2, sealed_copies=[])
    p_ref = add_erasure_proof(b, [])
    ea_ref = add_erasure_answer(
        b,
        evidential_support="sealed_key_service_proof",
        confirmed_copies=[],
        proof_ref=p_ref,
    )
    register(
        "erasure-l2-empty-copies-vacuous-rejected",
        "V8: Empty sealedServiceCopies with sealed_key_service_proof fails instead of passing vacuously.",
        b,
        "failed",
        [make_finding(layer=3, subject=ea_ref, check="erasure_l2_proof", result="failed", code="erasure_proof_invalid_or_missing_l2", category="cryptographic_proof", about=SESSION_1_URI)],
    )

    # 77. erasure-l2-institution-claim-rejected
    b = BundleBuilder(custody_level=2)
    ea_ref = add_erasure_answer(
        b,
        evidential_support="institution_claim",
        confirmed_copies=[],
        proof_ref=None,
    )
    register(
        "erasure-l2-institution-claim-rejected",
        "V8: Level 2 destroyed entry with evidentialSupport=institution_claim fails with erasure_institution_claim_at_l2.",
        b,
        "failed",
        [make_finding(layer=3, subject=ea_ref, check="erasure_l2_proof", result="failed", code="erasure_institution_claim_at_l2", category="cryptographic_proof", about=SESSION_1_URI)],
    )

    # 78. erasure-l2-duplicate-copy-confirmation-rejected
    b = BundleBuilder(custody_level=2)
    p_ref = add_erasure_proof(
        b,
        [("copy-a", KEYS["copy_a"]), ("copy-b", KEYS["copy_b"])],
        duplicate_copy=("copy-a", KEYS["attacker"]),
    )
    ea_ref = add_erasure_answer(
        b,
        evidential_support="sealed_key_service_proof",
        confirmed_copies=["copy-a", "copy-b"],
        proof_ref=p_ref,
    )
    register(
        "erasure-l2-duplicate-copy-confirmation-rejected",
        "V8: Duplicate copyId in copyConfirmations fails deterministically in both verifiers.",
        b,
        "failed",
        [make_finding(layer=3, subject=ea_ref, check="erasure_l2_proof", result="failed", code="erasure_proof_invalid_or_missing_l2", category="cryptographic_proof", about="copy-a")],
    )

    # 79. salted-content-unreferenced-tampered-rejected
    b = BundleBuilder()
    bad_sref = "bytes:sha256+salt:" + ("0" * 64)
    b.salted_content[bad_sref] = {"bytes": b64(b"yes"), "salt": b64(salt_bytes)}
    register(
        "salted-content-unreferenced-tampered-rejected",
        "V9: Unreferenced saltedContent entry with mismatched digest fails with salted_content_digest_mismatch.",
        b,
        "failed",
        [make_finding(layer=1, subject=bad_sref, check="salted_content_ref", result="failed", code="salted_content_digest_mismatch", category="cryptographic_proof", about=bad_sref)],
    )

    # 80. salted-content-empty-plaintext-valid
    b = BundleBuilder()
    endorse_person1(b)
    empty_sref = salted_ref(salt_bytes, b"")
    b.salted_content[empty_sref] = {"bytes": "", "salt": b64(salt_bytes)}
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        explanation_ref=empty_sref,
    )
    register(
        "salted-content-empty-plaintext-valid",
        "V9: 0-byte salted plaintext (bytes: \"\") with 32-byte salt passes as cryptographic_proof.",
        b,
        "ok",
        [
            make_finding(layer=1, subject=basis_ref, check="salted_content_ref", result="ok", code="ok", category="cryptographic_proof", about=empty_sref),
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
        ],
    )

    # 81. checkpoint-trusted-pin-catches-stripped-fork-rejected
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
        body={"seals": [b.chain_ref]},
    )
    b.checkpoints.append(ckpt_ref)
    trusted_ref = "evidence:sha256:" + ("b" * 64)
    b.trusted_checkpoints = [{"ref": trusted_ref, "seq": 1}]
    register(
        "checkpoint-trusted-pin-catches-stripped-fork-rejected",
        "V10: Reader-supplied trustedCheckpoints catches a forked checkpoint even when bundle.pinnedCheckpoints is stripped.",
        b,
        "failed",
        [make_finding(layer=3, subject=ckpt_ref, check="checkpoint_and_unlock_log", result="failed", code="checkpoint_fork_or_stale", category="cryptographic_proof", about=trusted_ref)],
    )

    # 82. checkpoint-non-monotonic-rejected
    b = BundleBuilder(custody_level=2)
    b.endorse(
        subject_key=KEYS["checkpoint"],
        kinds=["provenance.r5e.io/v2/Checkpoint"],
        acts_for=f"urn:r5e:node:{DEPLOYMENT_NAME}",
        role="checkpointer",
        captured_at="2026-11-22T11:02:30Z",
    )
    ckpt1 = b.add_record(
        kind="Checkpoint",
        stream=CKPT_STREAM,
        actor=f"urn:r5e:node:{DEPLOYMENT_NAME}",
        captured_at="2026-11-22T12:09:00Z",
        signers=[KEYS["checkpoint"]],
        schema_ref=BASE_DEFS["provenance.r5e.io/v2/Checkpoint"][0],
        body={"seals": [b.chain_ref]},
    )
    ckpt2 = b.add_record(
        kind="Checkpoint",
        stream=CKPT_STREAM,
        actor=f"urn:r5e:node:{DEPLOYMENT_NAME}",
        captured_at="2026-11-22T12:10:00Z",
        signers=[KEYS["checkpoint"]],
        schema_ref=BASE_DEFS["provenance.r5e.io/v2/Checkpoint"][0],
        body={"seals": [b.chain_ref]},
    )
    b.checkpoints.extend([ckpt2, ckpt1])
    register(
        "checkpoint-non-monotonic-rejected",
        "V10: Non-monotonic bundle.checkpoints [seq 2, seq 1] fails with checkpoint_fork_or_stale.",
        b,
        "failed",
        [make_finding(layer=3, subject=ckpt1, check="checkpoint_and_unlock_log", result="failed", code="checkpoint_fork_or_stale", category="cryptographic_proof", about="seq:1")],
    )

    # 83. disclosure-provided-refs-valid
    b = BundleBuilder(custody_level=1)
    payload_ref = b.add_blob(b"Disclosed session payload")
    b.add_record(
        kind="Observation",
        stream=SESS_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:05:00Z",
        signers=[KEYS["institution"]],
        session=SESSION_1_URI,
        body={"contentRefs": [payload_ref], "topic": "user_message"},
    )
    b.add_record(
        kind="Disclosure",
        stream=GOV_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:06:00Z",
        signers=[KEYS["institution"]],
        body={
            "outcome": "provided",
            "providedRefs": [payload_ref],
            "reason": "Authorized subject access disclosure",
            "recipient": RECIPIENT_URI,
            "requestedRefs": [payload_ref],
        },
    )
    register(
        "disclosure-provided-refs-valid",
        "V10: Carried session blob covered by Disclosure (outcome=provided, providedRefs) passes cleanly.",
        b,
        "ok",
        [],
    )

    # 84. unlock-log-cross-session-release-rejected
    b = BundleBuilder(custody_level=1)
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref, targets=[SESSION_1_URI])
    fp = bytes_ref(b"released-session-1")
    rcpt_ref = b.add_release_receipt(request_ref=req_ref, outcome="released", released_fingerprint=fp)
    b.add_key(KEYS["operator"])
    b.unlock_log.append(
        {
            "entryId": "unlock-cross-001",
            "operatorKey": KEYS["operator"].keyid,
            "releaseRef": rcpt_ref,
            "session": SESSION_2_URI,
            "unlockedAt": "2026-11-22T12:08:00Z",
        }
    )
    register(
        "unlock-log-cross-session-release-rejected",
        "V10: unlockLog citing a ReleaseReceipt for session 1 to unlock session 2 fails with unlock_without_release_record.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="ok", code="ok", category="mechanical_check", about=fp),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject="unlock-cross-001", check="checkpoint_and_unlock_log", result="failed", code="unlock_without_release_record", category="mechanical_check", about=SESSION_2_URI),
        ],
    )

    # 85. unrecorded-salted-plaintext-rejected
    b = BundleBuilder(custody_level=1)
    s_plain = b"Unrecorded salted session plaintext"
    obs_sref = salted_ref(salt_bytes, s_plain)
    b.salted_content[obs_sref] = {"bytes": b64(s_plain), "salt": b64(salt_bytes)}
    obs_ref = b.add_record(
        kind="Observation",
        stream=SESS_STREAM,
        actor=INSTITUTION_URI,
        captured_at="2026-11-22T12:05:00Z",
        signers=[KEYS["institution"]],
        session=SESSION_1_URI,
        body={"contentRefs": [obs_sref], "topic": "salted_user_message"},
    )
    register(
        "unrecorded-salted-plaintext-rejected",
        "V10: Carried saltedContent plaintext on a session record without Disclosure/ReleaseReceipt fails V10c.",
        b,
        "failed",
        [
            make_finding(layer=1, subject=obs_ref, check="salted_content_ref", result="ok", code="ok", category="cryptographic_proof", about=obs_sref),
            make_finding(layer=3, subject=obs_ref, check="checkpoint_and_unlock_log", result="failed", code="unrecorded_plaintext_in_bundle", category="mechanical_check", about=obs_sref),
        ],
    )

    # 86. embedded-sig-spoofed-key-bytes-v4-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    rid = "req-a11-spoof-0123456789abcdef0123456789"
    spoof_app = b.sign_release_approval(
        approver=KEYS["attacker"],
        request_id=rid,
        recipient_key=KEYS["recipient"].keyid,
        basis_ref=basis_ref,
        contract_version=b.chain_ref or "v1",
        signer_key_override=KEYS["approver_hw"].keyid,
    )
    req_ref = b.add_release_request(basis_ref=basis_ref, request_id=rid, approvals=[spoof_app])
    b.raw_key_overrides[KEYS["approver_hw"].keyid] = {
        "algorithm": "ed25519",
        "bytes": b64(KEYS["attacker"].pub_raw),
        "keyid": KEYS["approver_hw"].keyid,
    }
    register(
        "embedded-sig-spoofed-key-bytes-v4-rejected",
        "Embedded key-ID binding: replacing approver_hw key bytes in bundle.keys with attacker key fails V4.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="failed", code="approval_signature_invalid", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 87. contract-roots-changed-reordered-partial-update-ok
    b = BundleBuilder(custody_level=2, recovery_keys=[KEYS["recovery_1"]])
    b.add_record(
        kind="RootsChanged",
        stream=START_STREAM,
        actor=f"urn:r5e:root:{DEPLOYMENT_NAME}",
        captured_at="2026-11-22T11:01:30Z",
        signers=[KEYS["recovery_1"]],
        schema_ref=A11_DEFS["provenance.r5e.io/v2/RootsChanged"][0],
        body={
            "authorization": "recovery",
            "chain": b.chain_ref,
            "custodyLevel": 2,
            "reason": "Partial update preserving inherited witnessKeys and sealedServiceCopies",
            "replaces": b.chain_ref,
            "roots": [{"key": KEYS["root"].keyid, "publicKey": KEYS["root"].public_key_obj()}],
            "signer": KEYS["recovery_1"].keyid,
            "signerKey": KEYS["recovery_1"].public_key_obj(),
            "threshold": 1,
        },
    )
    # Reorder: move RootsChanged before Deployment in bundle.records
    dep_idx = next(
        i for i, r in enumerate(b.records) if json.loads(base64.b64decode(r["envelope"]["payload"]))["kind"] == "Deployment"
    )
    rc_rec = b.records.pop()
    b.records.insert(dep_idx, rc_rec)
    p_ref = add_erasure_proof(b, [("copy-a", KEYS["copy_a"]), ("copy-b", KEYS["copy_b"])])
    ea_ref = add_erasure_answer(
        b,
        evidential_support="sealed_key_service_proof",
        confirmed_copies=["copy-a", "copy-b"],
        proof_ref=p_ref,
    )
    register(
        "contract-roots-changed-reordered-partial-update-ok",
        "Historical contract resolution: RootsChanged placed before Deployment in bundle.records still inherits sealedServiceCopies.",
        b,
        "ok",
        [make_finding(layer=3, subject=ea_ref, check="erasure_l2_proof", result="ok", code="ok", category="cryptographic_proof", about=SESSION_1_URI)],
    )

    # 88. contract-later-downgrade-does-not-exempt-earlier-l2-receipt-rejected
    b = BundleBuilder(custody_level=2, recovery_keys=[KEYS["recovery_1"]])
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(subjects=[PERSON_1_URI], signers=[KEYS["institution"], KEYS["person1"]])
    req_ref = b.add_release_request(basis_ref=basis_ref, contract_version=b.chain_ref)
    fp = bytes_ref(b"released-under-l2-before-downgrade")
    rcpt_ref = b.add_release_receipt(
        request_ref=req_ref,
        outcome="released",
        released_fingerprint=fp,
        witness_receipt_ref=None,
        captured_at="2026-11-22T12:02:10Z",
    )
    b.add_record(
        kind="RootsChanged",
        stream=START_STREAM,
        actor=f"urn:r5e:root:{DEPLOYMENT_NAME}",
        captured_at="2026-11-22T12:15:00Z",
        signers=[KEYS["recovery_1"]],
        schema_ref=A11_DEFS["provenance.r5e.io/v2/RootsChanged"][0],
        body={
            "authorization": "recovery",
            "chain": b.chain_ref,
            "custodyLevel": 1,
            "reason": "Later downgrade to Level 1",
            "replaces": b.chain_ref,
            "roots": [{"key": KEYS["root"].keyid, "publicKey": KEYS["root"].public_key_obj()}],
            "signer": KEYS["recovery_1"].keyid,
            "signerKey": KEYS["recovery_1"].public_key_obj(),
            "threshold": 1,
        },
    )
    register(
        "contract-later-downgrade-does-not-exempt-earlier-l2-receipt-rejected",
        "Historical contract pinning: later RootsChanged downgrading custodyLevel to 1 does not exempt earlier L2 ReleaseReceipt.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=rcpt_ref, check="release_receipt_fingerprint", result="failed", code="witness_receipt_missing_l2", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="ok", code="ok", category="cryptographic_proof", about=KEYS["approver_hw"].keyid),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
    )

    # 89. threshold-2-pow-32-not-truncated-rejected
    b = BundleBuilder()
    endorse_hw_approver(b)
    endorse_person1(b)
    basis_ref = b.add_basis(
        subjects=[PERSON_1_URI],
        signers=[KEYS["institution"], KEYS["person1"]],
        threshold=4294967296,
    )
    req_ref = b.add_release_request(basis_ref=basis_ref, approver=KEYS["approver_hw"])
    register(
        "threshold-2-pow-32-not-truncated-rejected",
        "Integer safety: approvalRule.threshold=2^32 is never truncated to 0 on 32-bit targets.",
        b,
        "failed",
        [
            make_finding(layer=2, subject=basis_ref, check="basis_signatures", result="ok", code="ok", category="mechanical_check"),
            make_finding(layer=2, subject=req_ref, check="release_request_approvals", result="failed", code="approval_threshold_not_met", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_declared_power", result="ok", code="ok", category="mechanical_check", about=basis_ref),
            make_finding(layer=3, subject=req_ref, check="basis_overlay_order", result="ok", code="ok", category="mechanical_check", about=basis_ref),
        ],
        baseline_clean=False,
    )

    # 90. malformed-a11-export-members-rejected
    b = BundleBuilder()
    b.pinned_checkpoints.append({})
    b.unlock_log.append(42)
    b.salted_content["not-a-ref"] = 42  # type: ignore[assignment]
    register(
        "malformed-a11-export-members-rejected",
        "Wire validation: malformed nested entries in pinnedCheckpoints, unlockLog, and saltedContent fail with malformed_bundle without crashing.",
        b,
        "failed",
        [],
        baseline_clean=False,
    )

    return cases


def main() -> int:
    if CASES_OUT_DIR.exists():
        shutil.rmtree(CASES_OUT_DIR)
    CASES_OUT_DIR.mkdir(parents=True, exist_ok=True)
    cases = build_all_cases()
    assert len(cases) == 90, f"Expected 90 cases, got {len(cases)}"

    names = [c[0] for c in cases]
    assert len(names) == len(set(names)), "Duplicate case names detected"

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
