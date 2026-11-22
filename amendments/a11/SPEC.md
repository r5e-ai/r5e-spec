# A11: Custody, Authority, Releases, and Erasure

Amendment A11 to `provenance.r5e.io/v2`. The 28 frozen baseline definitions in `definitions/` are never edited; this amendment defines five new root kinds (`Basis`, `BasisOverlay`, `ReleaseRequest`, `ReleaseReceipt`, `ErasureAnswer`), additive extensions published as new definition versions for nine existing kinds (§2), the recovery form of `Succession` (§3), the salted content reference form (§4), offline verifier rules (§5), conformance test vector cases (§6), and the offline verifier wire contract (§7).

---

## 1. New root kinds in `provenance.r5e.io/v2`

Basis, release, and erasure records live in the root `provenance.r5e.io/v2` namespace so the relationship between a person and an institution is unambiguous across every deployment and verifier.

### 1.1 `provenance.r5e.io/v2/Basis`
*Immutable capture-time governance record stating who holds which powers, under what authority, and with what explanation. There is no `authority` label and no legal-basis enum ("consent", etc.): what a `Basis` authorises follows strictly from its content and who signed it.*

- **Substrate:** `event` · **Naming:** `content`
- **Signatures:**
  - Definition minimum: `1` (`signatures: 1` in `r5e.kind-definition/v1`; variable-signature verification enforced by V1).
  - Any `Basis` that names a human person (non-empty `subjects`, or a person URI in `actor` or `representative`) authorises **nothing** until **two** distinct, valid signatures are present: the institution's endorsed key and the person's or representative's key. A person without a personal signing key signs via their managed device session at sign-in, recorded explicitly via `signerKind: "device_session"` on that key's `Endorsement`.
  - A one-signature `Basis` is valid **only** for a machine workload that names no person (`subjects: []` and no person URI in `actor` or `representative`).
- **Required fields (`additionalProperties: false`):**
  - `institution`: `IdentityURI` — the organisation establishing the basis.
  - `actor`: `IdentityURI` — the signing person or workload acting under the basis.
  - `subjects`: `unique: true` array of `IdentityURI` — pseudonymous data subject(s) governed by the basis (kept distinct from `actor` and `representative`; empty only for non-person workload bases).
  - `grounds`: non-empty `unique: true` array of ground objects (`additionalProperties: false`), each with:
    - `groundId`: non-empty string (`maxLength: 128`).
    - `recordClasses`: non-empty `unique: true` array of strings (`maxLength: 128`).
    - `powers`: non-empty `unique: true` array of power-line objects (`additionalProperties: false`), each with:
      - `power`: enum `"capture" | "keep" | "read" | "inspect" | "disclose" | "dispose" | "hold" | "seal" | "derive" | "annotate" | "reclassify" | "train_on"`. (`read` is strictly the live-workload power for reading stored history into an active workload session; human review/audit uses `inspect`.)
      - `purpose`: non-empty string (`maxLength: 512`).
      - `approvalRule`: object (`additionalProperties: false`) naming `roles` (`unique: true` array of role strings) and `threshold` (positive integer `>= 1`).
      - `duration`: object (`additionalProperties: false`) carrying **exactly one** of `until` (RFC 3339 UTC timestamp) or `untilEvent` (non-empty event condition string, `maxLength: 256`).
    - Optional `instrument`: non-empty free-text string (`maxLength: 512`) stating the authority or policy relied on (r5e makes no claim about legal basis or consent).
  - `explanationRef`: content reference (`bytes:sha256:...` or salted content reference, §4) to the exact plain-language explanation shown to the person at signing.
- **Optional fields:**
  - `supersedesRef`: `evidence:sha256:...` — links to an earlier `Basis` when both parties accept an amendment and publish a new `Basis`.
  - `representative`: `IdentityURI` — guardian or legal representative acting for a subject.
  - `declaredTerms`: `unique: true` array of `{termId, scope, enforceable: boolean, statement}` (`additionalProperties: false`) — the person's own terms inside the `Basis` both signed. **Invariant:** `declaredTerms` and absent powers authorise no institutional act; the key service and offline verifiers reject any release citing a `declaredTerms` entry or an absent power.
  - `details`: `Details` (up to 64 bounded non-PII scalars).

### 1.2 `provenance.r5e.io/v2/BasisOverlay`
*Post-capture signed overlay referencing an immutable `Basis` record without mutating capture-time history.*

- **Substrate:** `event` · **Naming:** `content` · **Signatures:** `1` or `2` (definition minimum `1`; `amendment_proposal` may be signed by either party alone).
- **Required fields (`additionalProperties: false`):**
  - `basisRef`: `evidence:sha256:...` — immutable `Basis` record this overlay modifies, disputes, or proposes to amend.
  - `overlayType`: enum `"withdrawal" | "amendment_proposal" | "guardianship_transfer" | "role_succession" | "reclassification_rewrap" | "objection_or_rectification"`.
    - `amendment_proposal` may be signed by either party alone, authorises **nothing** on its own, and remains on the record whether or not accepted. Acceptance is recorded as a new `Basis` citing the prior one in `supersedesRef`.
  - `effectiveAt`: RFC 3339 UTC timestamp.
  - `summary`: non-empty string (`maxLength: 512`, no direct identifiers).
- **Optional fields:**
  - `supersedesRef`: `evidence:sha256:...`.
  - `subjects`: `unique: true` array of `IdentityURI`.
  - `representative`: `IdentityURI`.
  - `contentRefs`: `unique: true` array of content references (`bytes:sha256:...` or `bytes:sha256+salt:...`).
  - `details`: `Details`.
- **Evaluation order:** Both the key service and offline verifiers evaluate the capture-time `Basis` together with all of its `BasisOverlay` records in canonical order: chain order at Level 1, witness log order at Level 2.

### 1.3 `provenance.r5e.io/v2/ReleaseRequest` and `provenance.r5e.io/v2/ReleaseReceipt`
*Separates the frozen pre-release commitment, the registrar witness receipt (a separate object referencing the request's ordinary canonical hash — no circular reference), and the post-release delivery proof (`requested -> witnessed -> released`).*

- **`ReleaseRequest`** (`substrate: "event"`, `naming: "content"`, `signatures: >= 1`):
  - Frozen and signed **first**, before submission to the witness. Carries **no** `witnessReceiptRef`.
  - **Required (`additionalProperties: false`):**
    - `requestId`: non-empty high-entropy random nonce (`maxLength: 128`, at least 128 bits of entropy).
    - `basisRef`: `evidence:sha256:...`.
    - `groundId`: non-empty string (`maxLength: 128`).
    - `contractVersion`: non-empty string (`maxLength: 128`) — pinned deployment contract version at the registrar.
    - `targets`: non-empty `unique: true` array of `evidence:sha256:...` or session `IdentityURI`.
    - `subjects`: `unique: true` array of `IdentityURI` (may be empty only when none of the targeted sessions concern any human person). **Invariant:** `subjects` must equal the exact union of subjects across all `targets`.
    - `recipient`: `IdentityURI`.
    - `recipientKey`: key identifier (`key:...`) to which the release will be re-wrapped.
    - `timeWindow`: object (`additionalProperties: false`) with `notBefore` and `notAfter` (RFC 3339 UTC timestamps, `notBefore <= notAfter`).
    - `reason`: non-empty string (`maxLength: 512`).
    - `approvals`: non-empty `unique: true` array of approval signature objects (`additionalProperties: false`): `{signerKey, role, signature}` where `signature` is a cryptographic signature over canonical `(requestId, recipientKey, basisFingerprint, contractVersion)` (see §7.2). Whether `signerKey` is hardware-held is read exclusively from its `Endorsement` (§2), never self-declared in the request.
    - `sealed`: boolean.
  - **Optional:**
    - `power`: enum `"read" | "inspect" | "disclose" | "dispose" | "hold" | "seal" | "derive" | "annotate" | "reclassify" | "train_on"` (defaults to `"disclose"` when omitted).
    - `details`: `Details`.
- **Witness receipt (separate object):** Issued solely by the registrar witness (any second witness mirrors only) after logging the canonical `ReleaseRequest`. References the request by its ordinary canonical hash `requestHash = sha256(canonical(ReleaseRequest))`.
- **`ReleaseReceipt`** (`substrate: "event"`, `naming: "content"`, `signatures: 1`):
  - **Required (`additionalProperties: false`):**
    - `requestRef`: `evidence:sha256:...`.
    - `outcome`: enum `"released" | "delivered" | "failed" | "denied"` — `"released"` means handed over by the key service; `"delivered"` means acknowledged as received by the recipient.
  - **Conditional / Optional:**
    - `releasedFingerprint`: content digest (`bytes:sha256:...`). **Required** when `outcome` is `"released"` or `"delivered"`; omitted when `outcome` is `"denied"` or `"failed"`.
    - `witnessReceiptRef`: content reference (`bytes:sha256:...`) — **required** at Level 2.
    - `recipientKey`: key identifier (`key:...`).
    - `enclaveAttestationRef`: content reference (`bytes:sha256:...`).
    - `details`: `Details`.
- **Sealed entries:** Omitted from person-facing queries at both Level 1 and Level 2. At Level 1, a seal is a chain record inside the registrar's checkpoints; at Level 2, it is logged at the witness and disclosed to the overseer.

### 1.4 `provenance.r5e.io/v2/ErasureAnswer`
*Structured, truthful per-session response to an erasure request.*

- **Substrate:** `event` · **Naming:** `content` · **Signatures:** `1`.
- **Required fields (`additionalProperties: false`):**
  - `requestRef`: `evidence:sha256:...` or opaque request identifier (`maxLength: 128`).
  - `subject`: `IdentityURI` (pseudonymous).
  - `discoveryBoundary`: non-empty string (`maxLength: 1024`) — plain statement of the governed store and excluded external copies.
  - `sessions`: `unique: true` array of per-session objects (`additionalProperties: false`), each with:
    - `session`: `IdentityURI`.
    - `governedState`: enum `"destroyed" | "kept" | "refused" | "not_completed" | "unencrypted_deleted"`.
    - `evidentialSupport`: enum `"institution_claim" | "sealed_key_service_proof"`.
    - `derivedItems`: `unique: true` array of `{ref, state}` objects for governed derived items discovered via `derivedFrom`/`causes`.
    - `trainingWithdrawalEffect`: non-empty string (`maxLength: 512`).
    - `externalDisclosures`: `unique: true` array of `evidence:sha256:...` (`Disclosure` / `ReleaseReceipt` refs, including irreversible training disclosures).
    - `backupState`: object (`additionalProperties: false`) with `status` (`"ciphertext_erased" | "key_backup_aging_out" | "unencrypted_backup_aging_out"`) and optional `ageOutDate` (RFC 3339 UTC timestamp; required whenever `status` is `*_aging_out`).
    - `confirmedCopies`: `unique: true` array of sealed key-service copy IDs (`maxLength: 128`) that have confirmed key destruction as they catch up with the witness log.
    - Optional `preservationGrounds`: `unique: true` array of `{basisRef, holdRef?, sharedWithOtherSubject?: boolean, reviewAt}` (present when `kept` or `refused`).
    - Optional `proofRef`: content reference (`bytes:sha256:...`) — **required** when `governedState` is `"destroyed"` and `evidentialSupport` is `"sealed_key_service_proof"`.
- **Optional fields:**
  - `standingRestrictionNotice`: string (`maxLength: 1024`).
  - `correctsRef`: `evidence:sha256:...` — links a corrected answer issued after a seal ends.

---

## 2. Additive extensions to existing kinds (published as new definitions)

The 28 frozen baseline definitions are **never edited in place** — doing so would change their bytes and invalidate every existing `schemaRef`. Instead, each extended kind below is published as a **new definition version with a new `schemaRef`** in a `DefinitionPublished` record. Records written before this amendment continue to cite their original `schemaRef` and verify under the original definition; deployments admit both the baseline and extended definitions concurrently.

| Existing kind | Additive optional fields | Purpose |
| --- | --- | --- |
| `Deployment`, `RootsChanged`, `RootChangeApproval` | `custodyLevel` (`1 \| 2`), `witnessKeys` (`unique` array of key IDs), `overseerKey` (key ID), `approverRoles` (`unique` array of role bindings `{role, keys[]}`), `allowedMeasurements` (`unique` array of release measurement digests), `sealedServiceCopies` (`unique` array of copy IDs) | Pins the deployment contract at the registrar and prevents silent level downgrades or unapproved contract changes. |
| `Endorsement` | `keyStorage` (`"hardware" \| "personal_device" \| "administered_device_file"`), `hardwareAttestationRef` (content reference to the device's hardware attestation), `signerKind` (`"personal" \| "device_session"`), `recoveryRule` (`{threshold, recoveryKeys[]}`) | Records where a personal key is kept (`keyStorage: "hardware"` is treated as an unverified claim unless `hardwareAttestationRef` is present and verified), distinguishes device-session keys from personal keys, and pins a person's recovery rule at first endorsement. |
| `RetentionHold`, `RetentionHoldRelease` | `basisRef` (`evidence:sha256:...`), `reviewAt` (RFC 3339 UTC timestamp) | Binds institutional holds to a cited basis and a mandatory review date. |
| `PayloadDisposition` | `erasureAnswerRef` (`evidence:sha256:...`) | Keeps per-session disposal unchanged and links optionally to the structured `ErasureAnswer`. |
| `Disclosure` | `releaseRequestRef` (`evidence:sha256:...`), `releaseReceiptRef` (`evidence:sha256:...`) | Links disclosures to pre-release commitments and post-release receipts; pairs with redacted `PublishedView` for partial multi-person release. |

---

## 3. Recovery form of `Succession`

The existing `Succession` record proves continuity of a person's signing key by requiring both the old key and the new key to sign. When a person loses their old key, the extended `Succession` definition accepts a second proof form:

- **Standard form (unchanged):** valid signatures by both `predecessor` (`oldKey`) and `successor` (`newKey`), with `recoveryProof` omitted.
- **Recovery form (new):** valid signature by `successor` (`newKey`) **plus** `recoveryProof`:
  - `recoveryRuleRef`: `evidence:sha256:...` pointing to the person's registered `recoveryRule` (set at first endorsement or a prior valid `Succession`).
  - `approvals`: `unique: true` array of `{signerKey, signature}` objects over canonical `(oldKey, newKey, recoveryRuleRef)` (see §7.2) from keys named in `recoveryRule.recoveryKeys`, meeting `recoveryRule.threshold`.
  - **Invariant:** an institution's own endorsement key alone cannot satisfy `recoveryRule`; an institutional endorsement of a new key without either standard `Succession` or recovery-form `Succession` is a new identity, not continuous with the person.

---

## 4. Salted content reference (`bytes:sha256+salt:...`)

To prevent offline guessing of short or low-entropy payloads from a bare content digest (`bytes:sha256:<hex>`), content references accept a second, salted commitment form:

- **Form:** `bytes:sha256+salt:<64 lowercase hex digest>` where `digest = sha256("r5e-salted-content-v1\0" || salt || plaintext_bytes)` and `salt` is a random 32-byte per-object salt.
- **Storage invariant:** `salt` is stored **inside the encrypted content envelope, encrypted under the session key** — never in cleartext alongside the ciphertext or in database metadata. Destroying the session key destroys both the plaintext and the salt together.
- **Offline verification:**
  - When a bundle carries a disclosed salted content member in `saltedContent`, the member supplies `(salt, bytes)` and the verifier recomputes `sha256("r5e-salted-content-v1\0" || salt || plaintext_bytes)` and checks equality against the record's reference.
  - When the content is omitted or disposed, the verifier validates the reference syntax and reports `incomplete` (`unavailable_evidence`) without leaking whether the omitted payload matched any guessed plaintext.
- Existing `bytes:sha256:<64 hex>` references remain valid and unchanged.

---

## 5. Offline verifier rules (`r5e-verify-rs` and `r5e-verify-py`)

Both verifiers enforce these checks offline (no network access) and classify every A11 finding into one of four categories alongside `ok` / `failed` / `incomplete`:
`cryptographic_proof`, `mechanical_check`, `institutional_assertion`, or `unavailable_evidence`.

| # | Check name | Layer | Rule | Failure / finding code | Category |
| --- | --- | --- | --- | --- | --- |
| V1 | `basis_signatures` | 2 | Any `Basis` naming a human person must carry 2 distinct valid signatures (institution + person/representative or explicit `device_session`). A one-signature `Basis` is valid only when `subjects` is empty and no person is named. | `basis_missing_counter_signature` | `mechanical_check` |
| V2 | `basis_declared_power` | 3 | No institutional act (`ReleaseRequest`, `Disclosure`, `RetentionHold`) may cite a `declaredTerms` entry, an `amendment_proposal` overlay, or a power absent from the cited `groundId`. | `act_cites_declared_or_absent_power`, `proposal_authorises_nothing` | `mechanical_check` |
| V3 | `basis_overlay_order` | 3 | Evaluate `Basis` together with all applicable `BasisOverlay` records in canonical order (chain order at L1, witness order at L2); reject acts after withdrawal or past `duration` (`until` or triggered `untilEvent`). | `basis_power_withdrawn_or_expired` | `mechanical_check` |
| V4 | `release_request_approvals` | 2 | Every entry in `ReleaseRequest.approvals[]` must verify over canonical `(requestId, recipientKey, basisFingerprint, contractVersion)`, meet the cited power's `approvalRule`, and come from a key whose `Endorsement` carries `keyStorage: "hardware"` (with verified `hardwareAttestationRef` classified as `cryptographic_proof`, otherwise `institutional_assertion`). Additionally, `ReleaseRequest.subjects` must equal the exact union of subjects across all `targets`. | `approval_signature_invalid`, `approval_key_not_hardware`, `approval_threshold_not_met`, `release_subjects_incomplete` | `cryptographic_proof` / `mechanical_check` |
| V5 | `witness_receipt_binding` | 3 | Witness receipt is a separate object whose `requestHash` equals `sha256(canonical(ReleaseRequest))` and whose signature verifies under the deployment's pinned `witnessKeys`. Reject any `ReleaseRequest` embedding a receipt ref or a receipt from an unpinned witness. | `witness_receipt_hash_mismatch`, `witness_unpinned` | `cryptographic_proof` |
| V6 | `release_receipt_fingerprint` | 2 | `ReleaseReceipt` must carry `releasedFingerprint` iff `outcome` is `"released"` or `"delivered"`, and must carry `witnessReceiptRef` at Level 2. | `released_fingerprint_missing`, `witness_receipt_missing_l2` | `mechanical_check` |
| V7 | `succession_recovery` | 2 | `Succession` passes via either standard dual-key signature (`oldKey` + `newKey`) or recovery form (`newKey` + valid `recoveryProof` meeting registered `recoveryRule.threshold`). | `succession_recovery_threshold_not_met`, `succession_recovery_rule_unknown` | `cryptographic_proof` |
| V8 | `erasure_l2_proof` | 3 | For an `ErasureAnswer` entry with `governedState: "destroyed"` and `evidentialSupport: "sealed_key_service_proof"`: `proofRef` must verify for every copy listed in `confirmedCopies`, and every copy in `confirmedCopies` must belong to the contract's `sealedServiceCopies` (otherwise `failed`). If all listed confirmations verify but some copies in `sealedServiceCopies` have not yet confirmed, report `incomplete` (`erasure_copy_confirmation_pending`), not `failed`. Level 1 `"institution_claim"` is classified as `institutional_assertion`. | `erasure_proof_invalid_or_missing_l2`, `erasure_unknown_copy_id`, `erasure_copy_confirmation_pending` (`incomplete`) | `cryptographic_proof` / `institutional_assertion` |
| V9 | `salted_content_ref` | 1 | Carried salted content member `(salt, bytes)` must hash to the `bytes:sha256+salt:<hex>` digest; omitted content reports `unavailable_evidence`. | `salted_content_digest_mismatch` | `cryptographic_proof` / `unavailable_evidence` |
| V10 | `checkpoint_and_unlock_log` | 3 | Bundle checkpoints must progress monotonically and match pinned registrar checkpoints; at Level 1 any key-service unlock log entry lacking a matching release record is flagged; any carried plaintext payload lacking a matching `Disclosure` or `ReleaseReceipt` is flagged. | `checkpoint_fork_or_stale`, `unlock_without_release_record`, `unrecorded_plaintext_in_bundle` | `cryptographic_proof` / `mechanical_check` |
| V11 | `definition_coexistence` | 1 | Records citing a baseline `schemaRef` verify under the baseline definition even when a newer extended definition for the same kind is also published in the bundle. | *(passes `ok`)* | `mechanical_check` |

---

## 6. Conformance test vector cases

All 33 conformance test vector cases live under `amendments/a11/cases/<case-name>/{bundle.json, case.json, expected-report.json}` and are generated deterministically by `amendments/a11/generate_vectors.py`:

- **V1 (`basis_signatures`):**
  - `basis-person-two-signatures-valid` (institution + personal key -> `ok`)
  - `basis-person-device-session-valid` (institution + explicit `device_session` key -> `ok`)
  - `basis-person-one-signature-rejected` (institution only on person basis -> `failed`, `basis_missing_counter_signature`)
  - `basis-workload-no-person-valid` (empty `subjects`, one signature -> `ok`)
- **V2 (`basis_declared_power`):**
  - `release-cites-declared-term-rejected` -> `failed`, `act_cites_declared_or_absent_power`
  - `release-cites-absent-power-rejected` -> `failed`, `act_cites_declared_or_absent_power`
  - `proposal-alone-authorises-nothing` (`amendment_proposal` overlay without accepted new `Basis` -> `failed`, `proposal_authorises_nothing`)
- **V3 (`basis_overlay_order`):**
  - `release-after-withdrawal-overlay-rejected` -> `failed`, `basis_power_withdrawn_or_expired`
  - `release-before-withdrawal-overlay-valid` -> `ok`
- **V4 (`release_request_approvals`):**
  - `release-approval-hardware-key-valid` -> `ok`
  - `release-approval-administered-file-key-rejected` -> `failed`, `approval_key_not_hardware`
  - `release-approval-signature-mismatch-rejected` -> `failed`, `approval_signature_invalid`
  - `release-subjects-missing-person-rejected` -> `failed`, `release_subjects_incomplete`
  - `release-workload-empty-subjects-valid` -> `ok`
- **V5 (`witness_receipt_binding`):**
  - `witness-receipt-canonical-hash-valid` -> `ok`
  - `witness-receipt-hash-mismatch-rejected` -> `failed`, `witness_receipt_hash_mismatch`
  - `witness-receipt-unpinned-witness-rejected` -> `failed`, `witness_unpinned`
- **V6 (`release_receipt_fingerprint`):**
  - `release-receipt-released-with-fingerprint-valid` -> `ok`
  - `release-receipt-released-missing-fingerprint-rejected` -> `failed`, `released_fingerprint_missing`
  - `release-receipt-denied-without-fingerprint-valid` -> `ok`
- **V7 (`succession_recovery`):**
  - `succession-recovery-threshold-met-valid` -> `ok`
  - `succession-recovery-threshold-short-rejected` -> `failed`, `succession_recovery_threshold_not_met`
- **V8 (`erasure_l2_proof`):**
  - `erasure-l2-all-copies-confirmed-valid` -> `ok` (`cryptographic_proof`)
  - `erasure-l2-partial-copies-confirmed-incomplete` -> `incomplete` (`erasure_copy_confirmation_pending`)
  - `erasure-l2-unknown-copy-id-rejected` -> `failed`, `erasure_unknown_copy_id`
  - `erasure-l1-institution-claim-classified` -> `ok` (`institutional_assertion`)
- **V9 (`salted_content_ref`):**
  - `salted-content-carried-valid` -> `ok` (`cryptographic_proof`)
  - `salted-content-digest-mismatch-rejected` -> `failed`, `salted_content_digest_mismatch`
  - `salted-content-omitted-unavailable` -> `incomplete` (`unavailable_evidence`)
- **V10 (`checkpoint_and_unlock_log`):**
  - `bundle-unrecorded-plaintext-flagged` -> `failed`, `unrecorded_plaintext_in_bundle`
  - `l1-unlock-without-release-flagged` -> `failed`, `unlock_without_release_record`
  - `checkpoint-forked-flagged` -> `failed`, `checkpoint_fork_or_stale`
- **V11 (`definition_coexistence`):**
  - `old-definition-record-still-verifies` -> `ok` (`mechanical_check`)

---

## 7. Wire contract for offline verifiers (`r5e-verify-rs` and `r5e-verify-py`)

### 7.1 Additive top-level bundle members on `r5e.provenance-export/v2`

All four members below are **optional**. Baseline bundles without them continue to validate unchanged.

1. **`saltedContent`** (`object`, map from `bytes:sha256+salt:<64 lowercase hex>` to object):
   ```json
   {
     "bytes:sha256+salt:<64 hex>": {
       "salt": "<strict padded base64 of 32-byte salt>",
       "bytes": "<strict padded base64 of plaintext bytes>"
     }
   }
   ```
   - Digest formula: `sha256(b"r5e-salted-content-v1\x00" || salt || plaintext_bytes)`.
   - `salt` MUST decode to exactly 32 bytes.

2. **`witnessReceipts`** (`object`, map from `bytes:sha256:<64 lowercase hex>` to witness receipt object):
   ```json
   {
     "bytes:sha256:<receipt canonical sha256>": {
       "logIndex": 0,
       "loggedAt": "2026-11-22T12:00:00Z",
       "requestHash": "sha256:<64 hex>",
       "requestRef": "evidence:sha256:<64 hex>",
       "signature": "<strict padded base64>",
       "witnessKey": "key:<alg>:sha256:<64 hex>"
     }
   }
   ```
   - Map key MUST equal `"bytes:sha256:" + sha256(canonical_json(receipt_object))`.
   - `requestHash` MUST equal `"sha256:" + sha256(release_request_payload_bytes)`.
   - `signature` is a cryptographic signature by `witnessKey` over:
     `b"r5e-witness-receipt-v1\x00" || canonical_json({ "logIndex", "loggedAt", "requestHash", "requestRef", "witnessKey" })`.

3. **`unlockLog`** (`array` of Level 1 key-service unlock log entries):
   ```json
   [
     {
       "entryId": "unlock-001",
       "operatorKey": "key:ed25519:sha256:<64 hex>",
       "releaseRef": "evidence:sha256:<64 hex>",
       "session": "urn:r5e:session:...",
       "unlockedAt": "2026-11-22T12:05:00Z"
     }
   ]
   ```
   - `releaseRef` may be `null` or an `evidence:sha256:...` ref to a `ReleaseReceipt` (with `outcome` in `["released", "delivered"]`) or `Disclosure` covering `session`.

4. **`pinnedCheckpoints`** (`array` of pinned registrar checkpoint expectations):
   ```json
   [
     {
       "ref": "evidence:sha256:<64 hex>",
       "seq": 1
     }
   ]
   ```
   - Each entry pins the expected `Checkpoint` record `ref` at sequence `seq`.

### 7.2 Canonical signing inputs for embedded A11 proofs

All embedded signatures use the key's registered algorithm (Ed25519 / ES256 / ES384) over domain-separated canonical JSON (RFC 8785 / Core C1):

- **V4 Release approval (`ReleaseRequest.approvals[i].signature`):**
  `b"r5e-release-approval-v1\x00" || canonical_json({ "basisFingerprint": basisRef, "contractVersion": contractVersion, "recipientKey": recipientKey, "requestId": requestId })`
- **V7 Succession recovery (`Succession.recoveryProof.approvals[i].signature`):**
  `b"r5e-succession-recovery-v1\x00" || canonical_json({ "newKey": successor, "oldKey": predecessor, "recoveryRuleRef": recoveryRuleRef })`
- **V8 Level 2 erasure proof (`ErasureAnswer.sessions[i].proofRef` blob):**
  The blob is canonical JSON:
  ```json
  {
    "copyConfirmations": [
      {
        "copyId": "copy-a",
        "keyId": "key:ed25519:sha256:<64 hex>",
        "signature": "<strict padded base64>"
      }
    ],
    "destroyedAt": "2026-11-22T12:10:00Z",
    "session": "urn:r5e:session:..."
  }
  ```
  Each confirmation's `signature` is over:
  `b"r5e-erasure-proof-v1\x00" || canonical_json({ "copyId": copyId, "destroyedAt": destroyedAt, "session": session })`.

### 7.3 Variable-signature rule for A11 kinds

Baseline `r5e.kind-definition/v1` stores a single integer `signatures`. For the four A11 kinds whose valid signature count depends on record semantics, the definition declares `"signatures": 1` and verifiers apply:

- `provenance.r5e.io/v2/Basis`: 1 or 2 signatures (enforced by V1).
- `provenance.r5e.io/v2/BasisOverlay`: 1 or 2 signatures.
- `provenance.r5e.io/v2/ReleaseRequest`: `>= 1` signatures.
- `provenance.r5e.io/v2/Succession` (A11 extended definition): 2 signatures `[predecessor, successor]` (standard form, no `recoveryProof`) OR 1 signature `[successor]` (recovery form, with `recoveryProof`, enforced by V7).

### 7.4 A11 finding schema and vector expectation format

Each A11 finding has the shape:
```json
{
  "about": "<optional string or null>",
  "category": "cryptographic_proof | mechanical_check | institutional_assertion | unavailable_evidence",
  "check": "<V1..V11 check name>",
  "code": "<ok or finding code from §5>",
  "layer": 1,
  "result": "ok | failed | incomplete",
  "subject": "<evidence:sha256:... or bytes:sha256+salt:... or bundle>"
}
```
Each `expected-report.json` under `amendments/a11/cases/<case-name>/` specifies:
- `format`: `"r5e.provenance-verify-report/v2"`
- `amendment`: `"A11"`
- `verdict`: `"ok" | "failed" | "incomplete"`
- `baselineClean`: `true` (all baseline Layer 1/2/3 checks produce zero unexpected failures)
- `expectedA11Findings`: exact list of A11 findings expected for that vector case.
