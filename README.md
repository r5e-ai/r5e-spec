# r5e-spec

Frozen kind definitions, wire JSON schemas, conformance test vectors, and founding `r5e-api` Block 0 artifacts for Provenance v2 (`r5e.provenance-export/v2`).

## Contents

- [`definitions/`](definitions/): The 28 frozen Core v1 and Provenance v2 `r5e.kind-definition/v1` canonical JSON documents, package manifests (`r5e.core.json`, `r5e.provenance.json`), and `index.json` digest map.
- [`schemas/`](schemas/): The 5 wire JSON Schema (2020-12) definitions (`capture-profile.schema.json`, `epoch-manifest.schema.json`, `evidence-envelope.schema.json`, `export.schema.json`, `signed-evidence.schema.json`).
- [`cases/`](cases/): All 162 Provenance v2 conformance vector cases (`case.json`, `bundle.json`, `expected-report.json`).
- [`genesis/r5e-api/`](genesis/r5e-api/): Public founding artifacts for the `r5e-api` chain (`block-0-r5e-api.json`, `publications.json`, `r5e-root.pub.pem`, `r5e-publisher.pub.pem`, and `report-chain.canonical.json`).
- [`tests/verify_frozen_definitions.py`](tests/verify_frozen_definitions.py): Integrity test suite verifying that all 28 frozen definition files canonically hash byte-for-byte to the `DefinitionPublished` record (`evidence:sha256:f30a30f5e11c424dd0e07a7b02ebf8e7172f2065ac16d4d096dfcab8ae791a18`) in `genesis/r5e-api/block-0-r5e-api.json` and `genesis/r5e-api/publications.json`.

## `r5e-api` Block 0 Verification

Verified by three independent implementations (the Elixir reference implementation, clean-room Python `r5e-verify-py`, and clean-room Rust `r5e-verify-rs` — the latter two written from the specification and conformance vectors without reading the reference implementation), exercised across six execution surfaces (Elixir in-process, Gateway HTTP `/v1/evidence/verify`, an independent second-operator clean-tree run of the reference verifier, Python CLI, Rust native CLI, and zero-import WebAssembly), all producing byte-identical canonical report `c379ee8e555219daad6e2e0c3c7cf2ab0009a2823ea6f75eb914aaef3365d9ed` (`122 ok / 0 failed / 0 incomplete`).

## Integrity Verification

```sh
python3 tests/verify_frozen_definitions.py
```

## Contributing & License

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Licensed under Apache License 2.0 — see [`LICENSE`](LICENSE).
