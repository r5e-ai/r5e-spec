#!/usr/bin/env python3
"""Differential conformance test comparing r5e-verify-rs and r5e-verify-py CLIs
field-by-field across all 162 baseline cases and all 90 Amendment A11 cases."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

SPEC_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RS_BIN = SPEC_ROOT.parent / "r5e-verify-rs" / "target" / "debug" / "recurse_verify"
DEFAULT_PY_ROOT = SPEC_ROOT.parent / "r5e-verify-py"


def _build_args(case_dir: Path) -> list[str]:
    meta = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    args = ["provenance", str(case_dir / "bundle.json")]
    for tp in meta.get("trustedProfiles") or []:
        args += ["--trusted-profile", tp]
    for pub in meta.get("trustedPublishers") or []:
        args += ["--trusted-publisher", pub]
    for root in meta.get("trustedRoots") or []:
        args += ["--trusted-root", root]
    if meta.get("trustedChain"):
        args += ["--trusted-chain", meta["trustedChain"]]
    if meta.get("minStartSeq") is not None:
        args += ["--min-start-seq", str(meta["minStartSeq"])]
    for cp in meta.get("trustedCheckpoints") or []:
        args += ["--checkpoint", f"{cp['seq']}={cp['ref']}"]
    return args


def _run_suite(
    rs_bin: str, py_bin: str, py_cwd: Path, cases_dir: Path, label: str
) -> tuple[int, list[str]]:
    dirs = sorted(p for p in cases_dir.iterdir() if p.is_dir())
    diffs: list[str] = []
    for case_dir in dirs:
        args = _build_args(case_dir)
        r_rs = subprocess.run([rs_bin, *args], capture_output=True, text=True)
        r_py = subprocess.run(
            [py_bin, "-m", "r5e_verify", *args],
            capture_output=True,
            text=True,
            cwd=str(py_cwd),
        )
        if r_rs.returncode != r_py.returncode:
            diffs.append(
                f"[{label}] {case_dir.name}: exit code RS={r_rs.returncode} vs PY={r_py.returncode}"
            )
            continue
        j_rs = json.loads(r_rs.stdout)
        j_py = json.loads(r_py.stdout)
        if j_rs != j_py:
            bad = [k for k in sorted(set(j_rs) | set(j_py)) if j_rs.get(k) != j_py.get(k)]
            diffs.append(f"[{label}] {case_dir.name}: report differs on keys {bad}")
    print(f"{label}: checked {len(dirs)} cases, diffs={len(diffs)}", flush=True)
    return len(dirs), diffs


def main() -> int:
    rs_bin = os.environ.get("R5E_VERIFY_RS_BIN", str(DEFAULT_RS_BIN))
    py_root = Path(os.environ.get("R5E_VERIFY_PY_DIR", str(DEFAULT_PY_ROOT)))
    py_bin = os.environ.get("R5E_VERIFY_PY_BIN", str(py_root / ".venv" / "bin" / "python"))

    n_base, d_base = _run_suite(rs_bin, py_bin, py_root, SPEC_ROOT / "cases", "BASELINE")
    n_a11, d_a11 = _run_suite(
        rs_bin, py_bin, py_root, SPEC_ROOT / "amendments" / "a11" / "cases", "A11"
    )
    all_diffs = d_base + d_a11
    for line in all_diffs[:30]:
        print(line)
    print(f"TOTAL: {n_base + n_a11} cases checked, {len(all_diffs)} diffs")
    return 1 if all_diffs else 0


if __name__ == "__main__":
    raise SystemExit(main())
