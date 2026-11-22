#!/usr/bin/env python3
"""Verify byte-for-byte and canonical hash integrity of the 28 frozen definitions,
162 conformance vectors, and public r5e-api Block 0 founding artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import unittest
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFINITIONS_DIR = REPO_ROOT / "definitions"
SCHEMAS_DIR = REPO_ROOT / "schemas"
CASES_DIR = REPO_ROOT / "cases"
GENESIS_DIR = REPO_ROOT / "genesis" / "r5e-api"

EXPECTED_BLOCK_0_SHA256 = "a706c2bc8e4705e57e316d4549d3d0733290d242aefca3016f80ac824cf0d55a"
EXPECTED_PUBLICATIONS_SHA256 = "b26f95e10df37756cf04217d6a739138e0e188ed3ac3c01214054e19440b13f9"
EXPECTED_CANONICAL_REPORT_SHA256 = (
    "c379ee8e555219daad6e2e0c3c7cf2ab0009a2823ea6f75eb914aaef3365d9ed"
)
EXPECTED_CHAIN_REF = (
    "evidence:sha256:7c45caf3de9a3014b662d67c44705b6fdb180c06492abbb9e4a216828ef686c5"
)
EXPECTED_DEFINITION_PUBLISHED_REF = (
    "evidence:sha256:f30a30f5e11c424dd0e07a7b02ebf8e7172f2065ac16d4d096dfcab8ae791a18"
)
EXPECTED_ROOT_KEY_ID = (
    "key:ed25519:sha256:aeb2f4f7d81d87ce8e9f437fa5bada43d41d7cf5badcceffdf37403ddfee53fc"
)
EXPECTED_BOOTSTRAP_KEY_ID = (
    "key:ed25519:sha256:86b70d9bde96d3f437472a8d1d2cf86e81b80a8f399d9a532ec287b029fe7707"
)
EXPECTED_PUBLISHER_KEY_ID = (
    "key:es256:sha256:2685eeac8d06dd75811f6b14fb45bde55c657957e3adface2ff8b0379c31cc33"
)


def compute_key_id(alg: str, raw_pub: bytes) -> str:
    alg_bytes = alg.encode("ascii")
    assert len(alg_bytes) < 128
    digest = hashlib.sha256(bytes([len(alg_bytes)]) + alg_bytes + raw_pub).hexdigest()
    return f"key:{alg}:sha256:{digest}"


def _reject_float_or_constant(token: str) -> Any:
    raise ValueError(f"Non-integer JSON number or constant forbidden in canonical JSON: {token}")


def _utf16_sort_key(key: str) -> bytes:
    return key.encode("utf-16-be")


def encode_canonical_json(value: Any) -> bytes:
    """RFC 8785 / Core C1 canonical JSON encoding (no floats, UTF-16 code-unit key order)."""
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
        for k in sorted(value.keys(), key=_utf16_sort_key):
            if type(k) is not str:
                raise TypeError(f"Object key must be str, got {type(k)}")
            k_bytes = json.dumps(k, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            items.append(k_bytes + b":" + encode_canonical_json(value[k]))
        return b"{" + b",".join(items) + b"}"
    raise TypeError(f"Unsupported type for canonical JSON: {type(value)}")


def parse_strict_json(raw: bytes) -> Any:
    def no_dups(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for k, v in pairs:
            if k in obj:
                raise ValueError(f"Duplicate JSON key: {k!r}")
            obj[k] = v
        return obj

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=no_dups,
        parse_float=_reject_float_or_constant,
        parse_constant=_reject_float_or_constant,
    )


def extract_records_by_ref(bundle: dict[str, Any]) -> dict[str, tuple[bytes, dict[str, Any], list[str]]]:
    out: dict[str, tuple[bytes, dict[str, Any], list[str]]] = {}
    for entry in bundle["records"]:
        env = entry.get("envelope", entry)
        payload_bytes = base64.b64decode(env["payload"], validate=True)
        computed_ref = "evidence:sha256:" + hashlib.sha256(payload_bytes).hexdigest()
        if "ref" in entry:
            assert entry["ref"] == computed_ref, f"{entry['ref']} != {computed_ref}"
        payload = parse_strict_json(payload_bytes)
        assert encode_canonical_json(payload) == payload_bytes, f"Non-canonical payload for {computed_ref}"
        signers = [sig["keyid"] for sig in env["signatures"]]
        out[computed_ref] = (payload_bytes, payload, signers)
    return out


def extract_blobs_by_ref(bundle: dict[str, Any]) -> dict[str, bytes]:
    blobs: dict[str, bytes] = {}
    for bl in bundle["blobs"]:
        raw = base64.b64decode(bl["base64"], validate=True)
        computed_ref = "bytes:sha256:" + hashlib.sha256(raw).hexdigest()
        if "ref" in bl:
            assert bl["ref"] == computed_ref, f"{bl['ref']} != {computed_ref}"
        blobs[computed_ref] = raw
    return blobs


class FrozenDefinitionsIntegrityTests(unittest.TestCase):
    def test_public_founding_artifact_digests(self) -> None:
        b0_bytes = (GENESIS_DIR / "block-0-r5e-api.json").read_bytes()
        pub_bytes = (GENESIS_DIR / "publications.json").read_bytes()
        rep_bytes = (GENESIS_DIR / "report-chain.canonical.json").read_bytes()

        self.assertEqual(hashlib.sha256(b0_bytes).hexdigest(), EXPECTED_BLOCK_0_SHA256)
        self.assertEqual(hashlib.sha256(pub_bytes).hexdigest(), EXPECTED_PUBLICATIONS_SHA256)
        self.assertEqual(hashlib.sha256(rep_bytes).hexdigest(), EXPECTED_CANONICAL_REPORT_SHA256)

        rep = parse_strict_json(rep_bytes)
        self.assertEqual(encode_canonical_json(rep), rep_bytes)
        self.assertEqual(rep["summary"], {"failed": 0, "incomplete": 0, "ok": 122})
        self.assertEqual(rep["start"]["chain"], EXPECTED_CHAIN_REF)
        self.assertEqual(rep["start"]["deployment"], "r5e-api")

    def test_public_key_pems_match_published_key_ids(self) -> None:
        # Ed25519 SPKI DER has a fixed 12-byte ASN.1 header followed by 32 raw key bytes.
        root_pem = (GENESIS_DIR / "r5e-root.pub.pem").read_text(encoding="ascii")
        root_b64 = "".join(
            ln.strip() for ln in root_pem.splitlines() if not ln.startswith("-----")
        )
        root_spki = base64.b64decode(root_b64, validate=True)
        self.assertEqual(len(root_spki), 44)
        self.assertEqual(root_spki[:12], bytes.fromhex("302a300506032b6570032100"))
        root_raw = root_spki[12:]
        root_kid = compute_key_id("ed25519", root_raw)
        self.assertEqual(root_kid, EXPECTED_ROOT_KEY_ID)

        # P-256 uncompressed SPKI DER has a fixed 26-byte ASN.1 header followed by 65 SEC1 bytes (0x04 || X || Y).
        pub_pem = (GENESIS_DIR / "r5e-publisher.pub.pem").read_text(encoding="ascii")
        pub_b64 = "".join(
            ln.strip() for ln in pub_pem.splitlines() if not ln.startswith("-----")
        )
        pub_spki = base64.b64decode(pub_b64, validate=True)
        self.assertEqual(len(pub_spki), 91)
        self.assertEqual(
            pub_spki[:26],
            bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200"),
        )
        pub_sec1 = pub_spki[26:]
        self.assertEqual(pub_sec1[0], 0x04)
        pub_kid = compute_key_id("es256", pub_sec1)
        self.assertEqual(pub_kid, EXPECTED_PUBLISHER_KEY_ID)

    def test_all_28_frozen_definitions_match_block0_and_publications_byte_for_byte(self) -> None:
        b0 = parse_strict_json((GENESIS_DIR / "block-0-r5e-api.json").read_bytes())
        pubs = parse_strict_json((GENESIS_DIR / "publications.json").read_bytes())

        b0_records = extract_records_by_ref(b0)
        pub_records = extract_records_by_ref(pubs)
        b0_blobs = extract_blobs_by_ref(b0)
        pub_blobs = extract_blobs_by_ref(pubs)

        self.assertIn(EXPECTED_CHAIN_REF, b0_records)
        self.assertIn(EXPECTED_DEFINITION_PUBLISHED_REF, b0_records)
        self.assertIn(EXPECTED_DEFINITION_PUBLISHED_REF, pub_records)

        b0_dp_bytes, b0_dp_payload, b0_dp_signers = b0_records[EXPECTED_DEFINITION_PUBLISHED_REF]
        pub_dp_bytes, pub_dp_payload, pub_dp_signers = pub_records[EXPECTED_DEFINITION_PUBLISHED_REF]
        self.assertEqual(b0_dp_bytes, pub_dp_bytes)
        self.assertEqual(b0_dp_signers, [EXPECTED_PUBLISHER_KEY_ID])
        self.assertEqual(pub_dp_signers, [EXPECTED_PUBLISHER_KEY_ID])
        self.assertEqual(b0_dp_payload["apiVersion"], "provenance.r5e.io/v2")
        self.assertEqual(b0_dp_payload["kind"], "DefinitionPublished")

        published_list = b0_dp_payload["body"]["definitions"]
        self.assertEqual(len(published_list), 28)
        published_map = {item["kind"]: item["definition"] for item in published_list}
        self.assertEqual(len(published_map), 28)

        # Verify index.json matches the published definition map identically
        index_map = parse_strict_json((DEFINITIONS_DIR / "index.json").read_bytes())
        self.assertEqual(index_map, published_map)

        # Verify Deployment & ChainStarted inside block-0-r5e-api.json
        _, deployment_payload, deployment_signers = b0_records[EXPECTED_CHAIN_REF]
        self.assertEqual(deployment_payload["kind"], "Deployment")
        self.assertEqual(deployment_signers, [EXPECTED_BOOTSTRAP_KEY_ID, EXPECTED_ROOT_KEY_ID])

        chain_started = [
            p for _, p, _ in b0_records.values() if p.get("kind") == "ChainStarted"
        ]
        self.assertEqual(len(chain_started), 1)
        cs_map = {
            item["kind"]: item["definition"]
            for item in chain_started[0]["body"]["definitions"]
        }
        self.assertEqual(cs_map, published_map)

        # Enumerate all kind definition JSON files on disk (excluding index.json and package manifests)
        disk_def_files = sorted(
            p
            for p in DEFINITIONS_DIR.rglob("*.json")
            if p.parent != DEFINITIONS_DIR
        )
        self.assertEqual(len(disk_def_files), 28)

        for def_path in disk_def_files:
            rel_kind = def_path.relative_to(DEFINITIONS_DIR).with_suffix("").as_posix()
            self.assertIn(rel_kind, published_map, f"Unexpected definition file {rel_kind}")
            expected_ref = published_map[rel_kind]

            raw_bytes = def_path.read_bytes()
            parsed = parse_strict_json(raw_bytes)
            self.assertEqual(parsed["kind"], rel_kind)

            canonical_bytes = encode_canonical_json(parsed)
            # Assert the file on disk is already byte-for-byte canonical JSON
            self.assertEqual(
                raw_bytes,
                canonical_bytes,
                f"Definition file {rel_kind} is not exact canonical JSON on disk",
            )
            computed_ref = "bytes:sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
            self.assertEqual(
                computed_ref,
                expected_ref,
                f"Canonical digest mismatch for {rel_kind}: {computed_ref} != {expected_ref}",
            )
            # Assert exact byte-for-byte equality with CAS blobs in both bundles
            self.assertIn(expected_ref, b0_blobs)
            self.assertIn(expected_ref, pub_blobs)
            self.assertEqual(b0_blobs[expected_ref], raw_bytes)
            self.assertEqual(pub_blobs[expected_ref], raw_bytes)

    def test_162_conformance_vectors_and_5_schemas_present(self) -> None:
        schema_files = sorted(p.name for p in SCHEMAS_DIR.glob("*.schema.json"))
        self.assertEqual(
            schema_files,
            [
                "capture-profile.schema.json",
                "epoch-manifest.schema.json",
                "evidence-envelope.schema.json",
                "export.schema.json",
                "signed-evidence.schema.json",
            ],
        )

        case_dirs = sorted(p for p in CASES_DIR.iterdir() if p.is_dir())
        self.assertEqual(len(case_dirs), 162)
        for cdir in case_dirs:
            self.assertTrue((cdir / "case.json").is_file(), f"Missing case.json in {cdir.name}")
            self.assertTrue((cdir / "bundle.json").is_file(), f"Missing bundle.json in {cdir.name}")
            self.assertTrue(
                (cdir / "expected-report.json").is_file(),
                f"Missing expected-report.json in {cdir.name}",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
