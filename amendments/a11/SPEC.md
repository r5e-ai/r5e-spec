# A11: Custody, Authority, Releases, and Erasure

Amendment A11 to `provenance.r5e.io/v2`. The 28 frozen baseline definitions in `definitions/` are never edited; this amendment defines **five** new root kinds (`Basis`, `BasisOverlay`, `ReleaseRequest`, `ReleaseReceipt`, `ErasureAnswer`), additive extensions published as new definition versions for nine existing kinds (§2), the recovery form of `Succession` (§3), the salted content reference form (§4), offline verifier rules V1–V11 with complete finding classification and entry-point routing (§5), conformance test vector cases (§6), and the offline verifier wire contract (§7).

All timestamps in A11 records and wire objects MUST be UTC `Z`-terminated RFC 3339 (`YYYY-MM-DDTHH:MM:SS(.frac)?Z`, up to nanosecond precision).

---

## 1. Five new root kinds in `provenance.r5e.io/v2`

Basis, release, and erasure records live in the root `provenance.r5e.io/v2` namespace so the relationship between a person and an institution is unambiguous across every deployment and verifier.

### 1.1 `provenance.r5e.io/v2/Basis`
*Immutable capture-time governance record stating who holds which powers, under what authority, and with what explanation. There is no `authority` label and no legal-basis enum ("consent", etc.): what a `Basis` authorises follows strictly from its content and who signed it.*

- **Substrate:** `event` · **Naming:** `content`
- **Person-naming predicate (structural, zero URI-prefix heuristics):** A `Basis` names a human person **if and only if** `subjects` is non-empty OR `representative` is present (non-empty). `actor` is never inspected to infer whether a person is named.
- **Signatures:**
  - Definition minimum: `1` (`signatures: 1` in `r5e.kind-definition/v1`; variable-signature verification enforced by V1).
  - Any `Basis` that names a human person authorises **nothing** unless **exactly two** distinct, valid signatures are present:
    1. one key whose valid, active `Endorsement` covers `institution` (`actsFor == institution`), and
    2. one key whose valid, active `Endorsement` covers one of the named `subjects` or `representative` (`actsFor` in `subjects` or `actsFor == representative`), with `signerKind` equal to `"personal"` or `"device_session"`.
    Two institutional keys NEVER satisfy this rule.
  - When the second signer has `signerKind: "personal"`, V1 passes as `ok` (`code: "ok"`, category `mechanical_check`). When the second signer has `signerKind: "device_session"` (administered by the institution for a keyless person), V1 passes as `ok` with `code: "basis_person_signed_by_device_session"` and category **`institutional_assertion`**.
  - A one-signature `Basis` is valid **only** for a machine workload that names no person (`subjects: []` and no `representative`). To prevent an empty-`subjects` bypass, any `ReleaseRequest`, `Disclosure`, or `RetentionHold` may cite a `Basis` **only** if every subject of every targeted session/record is in `Basis.subjects` (`basis_subjects_do_not_cover_targets`).
- **Required fields (`additionalProperties: false`):**
  - `institution`: `IdentityURI` — the organisation establishing the basis.
  - `actor`: `IdentityURI` — the signing person or workload acting under the basis.
  - `subjects`: `unique: true` array of `IdentityURI` — pseudonymous data subject(s) governed by the basis (kept distinct from `actor` and `representative`; empty only for non-person workload bases).
  - `grounds`: non-empty `unique: true` array of ground objects (`additionalProperties: false`), each with:
    - `groundId`: non-empty string (`maxLength: 128`).
    - `recordClasses`: non-empty `unique: true` array of non-empty strings (`maxLength: 128`).
    - `powers`: non-empty `unique: true` array of power-line objects (`additionalProperties: false`), each with:
      - `power`: enum `"capture" | "keep" | "read" | "inspect" | "disclose" | "dispose" | "hold" | "seal" | "derive" | "annotate" | "reclassify" | "train_on"`. (`read` is strictly the live-workload power for reading stored history into an active workload session; human review/audit uses `inspect`.)
      - `purpose`: non-empty string (`maxLength: 512`).
      - `approvalRule`: object (`additionalProperties: false`) naming `roles` (non-empty `unique: true` array of non-empty strings, `maxLength: 128`) and `threshold` (integer `1..64`).
      - `duration`: object (`additionalProperties: false`) carrying **exactly one** of `until` (UTC `Z` RFC 3339 timestamp) or `untilEvent` (non-empty event condition string, `maxLength: 256`).
    - Optional `instrument`: non-empty free-text string (`maxLength: 512`) stating the authority or policy relied on (r5e makes no claim about legal basis or consent).
  - `explanationRef`: content reference (`bytes:sha256:...` or `bytes:sha256+salt:...`, §4) to the exact plain-language explanation shown to the person at signing.
- **Optional fields:**
  - `supersedesRef`: `ref: {evidence: true}` — links to an earlier `Basis` when both parties accept an amendment and publish a new `Basis`.
  - `representative`: non-empty `IdentityURI` — guardian or legal representative acting for a subject.
  - `declaredTerms`: `unique: true` array of `{termId (non-empty, maxLength 128), scope (non-empty, maxLength 256), enforceable: boolean, statement (non-empty, maxLength 1024)}` (`additionalProperties: false`) — the person's own terms inside the `Basis` both signed. **Invariant:** `declaredTerms` and absent powers authorise no institutional act; the key service and offline verifiers reject any act citing a `declaredTerms` entry or an absent power.
  - `details`: `Details` (up to 64 bounded non-PII scalars).

### 1.2 `provenance.r5e.io/v2/BasisOverlay`
*Post-capture signed overlay referencing an immutable `Basis` record without mutating capture-time history.*

- **Substrate:** `event` · **Naming:** `content` · **Signatures:** `1` or `2` (definition minimum `1`; matching the authority required by `overlayType`; `amendment_proposal` may be signed by either party alone).
- **Required fields (`additionalProperties: false`):**
  - `basisRef`: `ref: {evidence: true}` — immutable `Basis` record this overlay modifies, disputes, or proposes to amend.
  - `overlayType`: enum `"withdrawal" | "amendment_proposal" | "guardianship_transfer" | "role_succession" | "reclassification_rewrap" | "objection_or_rectification"`.
    - `amendment_proposal` may be signed by either party alone, authorises **nothing** on its own, and remains on the record whether or not accepted. Acceptance is recorded as a new `Basis` citing the prior one in `supersedesRef`.
  - `effectiveAt`: UTC `Z` RFC 3339 timestamp.
  - `summary`: non-empty string (`maxLength: 512`, no direct identifiers).
- **Optional fields:**
  - `supersedesRef`: `ref: {evidence: true}`.
  - `subjects`: `unique: true` array of `IdentityURI`.
  - `representative`: non-empty `IdentityURI`.
  - `contentRefs`: `unique: true` array of content references (`bytes:sha256:...` or `bytes:sha256+salt:...`, §4).
  - `details`: `Details`.
- **Evaluation order:**
  - At **Level 1**, `BasisOverlay` records are ordered by stream position `(stream, seq)` (and across streams by `(capturedAt, ref)`); a backdated `effectiveAt` cannot override a later stream position on the same stream, and an earlier stream position cannot be evaded by backdating a later act's `capturedAt`.
  - At **Level 2**, `BasisOverlay` records are ordered by their registrar witness `logIndex` (when witnessed; otherwise stream/capture order).
  - Overlay signers must hold valid authority for the overlay type (e.g., `withdrawal` must be signed by a key endorsed for a named `subject`, `representative`, or `institution`).

### 1.3 `provenance.r5e.io/v2/ReleaseRequest` and `provenance.r5e.io/v2/ReleaseReceipt`
*Separates the frozen pre-release commitment, the registrar witness receipt (a separate object referencing the request's ordinary canonical hash — no circular reference), and the post-release delivery proof (`requested -> witnessed -> released`).*

- **`ReleaseRequest`** (`substrate: "event"`, `naming: "content"`, `signatures: >= 1`):
  - Frozen and signed **first**, before submission to the witness. Carries **no** `witnessReceiptRef`.
  - **Required (`additionalProperties: false`):**
    - `requestId`: non-empty high-entropy random nonce (`minLength: 22`, `maxLength: 128`, pattern `^[^\s]{22,128}$`, >= 128 bits of entropy). Makes the witness's canonical request hash unguessable while allowing any holder of the request to recompute it.
    - `basisRef`: `ref: {evidence: true}` pointing to a `Basis` record.
    - `groundId`: non-empty string (`maxLength: 128`).
    - `contractVersion`: non-empty string (`maxLength: 128`) — pinned deployment contract version (`Deployment` or `RootsChanged` ref/version) active at the time of the request.
    - `targets`: non-empty `unique: true` array of target references, each strictly matching either `^evidence:sha256:[0-9a-f]{64}$` or `^urn:r5e:session:[^\s]+$`.
    - `subjects`: `unique: true` array of `IdentityURI` (may be empty only when none of the targeted sessions concern any human person). **Invariant:** `subjects` MUST equal the exact union of subjects across all `targets` (and every target subject MUST be covered by `Basis.subjects`); omitting or adding a subject fails verification.
    - `recipient`: `IdentityURI`.
    - `recipientKey`: key identifier (`key:...`) to which the release will be re-wrapped.
    - `timeWindow`: object (`additionalProperties: false`) with `notBefore` and `notAfter` (UTC `Z` RFC 3339 timestamps, `notBefore <= notAfter`).
    - `reason`: non-empty string (`maxLength: 512`).
    - `approvals`: non-empty `unique: true` array (max 64 entries) of approval signature objects (`additionalProperties: false`): `{signerKey, role, signature}` where `signature` is a cryptographic signature over canonical `(basisFingerprint, contractVersion, recipientKey, requestId)` (§7.4). Whether `signerKey` is hardware-held and holds `role` is read exclusively from its active `Endorsement` and the deployment's pinned `approverRoles` (§2), never self-declared in the request.
    - `sealed`: boolean.
  - **Optional:**
    - `power`: enum `"read" | "inspect" | "disclose" | "derive" | "train_on"` — names the specific power exercised from `groundId` (defaults to `"disclose"` when omitted).
    - `details`: `Details`.
- **Witness receipt (separate object):** Issued solely by the registrar witness (any second witness mirrors only) after logging the canonical `ReleaseRequest`. References the request by its ordinary canonical hash `requestHash = "sha256:" || hex(sha256(release_request_payload_bytes))` and signs `b"r5e-witness-receipt-v1\x00" || canonical_json(receipt_without_signature)`.
- **`ReleaseReceipt`** (`substrate: "event"`, `naming: "content"`, `signatures: 1`):
  - **Required (`additionalProperties: false`):**
    - `requestRef`: `ref: {evidence: true}` pointing to a `ReleaseRequest`.
    - `outcome`: enum `"released" | "delivered" | "failed" | "denied"` — `"released"` means handed over by the key service; `"delivered"` means acknowledged as received by the recipient.
  - **Conditional / Optional:**
    - `releasedFingerprint`: content digest (`bytes:sha256:...`). **Required** when `outcome` is `"released"` or `"delivered"` (enforced by schema `requires` and V6 `released_fingerprint_missing`); **forbidden** when `outcome` is `"denied"` or `"failed"` (V6 `released_fingerprint_unexpected`).
    - `witnessReceiptRef`: content reference (`bytes:sha256:...`) — **required** at Level 2 (V6 `witness_receipt_missing_l2`).
    - `recipientKey`: key identifier (`key:...`).
    - `enclaveAttestationRef`: content reference (`bytes:sha256:...` or `bytes:sha256+salt:...`).
    - `details`: `Details`.
- **Sealed entries:** Omitted from person-facing queries at both Level 1 and Level 2. At Level 1, a seal is a chain record inside the registrar's checkpoints; at Level 2, it is logged at the witness and disclosed to the overseer.

### 1.4 `provenance.r5e.io/v2/ErasureAnswer`
*Structured, truthful per-session response to an erasure request.*

- **Substrate:** `event` · **Naming:** `content` · **Signatures:** `1`.
- **Required fields (`additionalProperties: false`):**
  - `requestRef`: non-empty string (`maxLength: 128`, `evidence:sha256:...` or opaque request identifier).
  - `subject`: `IdentityURI` (pseudonymous).
  - `discoveryBoundary`: non-empty string (`maxLength: 1024`) — plain statement of the governed store and excluded external copies.
  - `sessions`: `unique: true` array of per-session objects (`additionalProperties: false`), each with:
    - `session`: `IdentityURI`.
    - `governedState`: enum `"destroyed" | "kept" | "refused" | "not_completed" | "unencrypted_deleted"`.
    - `evidentialSupport`: enum `"institution_claim" | "sealed_key_service_proof"`.
    - `derivedItems`: `unique: true` array of `{ref, state}` objects (`ref` permits `evidence:sha256:...`, `event:sha256:...`, `bytes:sha256:...`, or `bytes:sha256+salt:...`).
    - `trainingWithdrawalEffect`: non-empty string (`maxLength: 512`).
    - `externalDisclosures`: `unique: true` array of `ref: {evidence: true}` (`Disclosure` / `ReleaseReceipt` refs, including irreversible training disclosures).
    - `backupState`: object (`additionalProperties: false`) with `status` (`"ciphertext_erased" | "key_backup_aging_out" | "unencrypted_backup_aging_out"`) and optional `ageOutDate` (UTC `Z` RFC 3339 timestamp; required whenever `status` is `*_aging_out`).
    - `confirmedCopies`: `unique: true` array of non-empty sealed key-service copy IDs (`maxLength: 128`) that have confirmed key destruction as they catch up with the witness log.
    - Optional `preservationGrounds`: non-empty `unique: true` array of `{basisRef, holdRef?, sharedWithOtherSubject?: boolean, reviewAt (UTC Z)}` — **required** when `governedState` is `"kept"` or `"refused"`.
    - Optional `proofRef`: content reference (`bytes:sha256:...` or `bytes:sha256+salt:...`) — **required** when `governedState` is `"destroyed"` and `evidentialSupport` is `"sealed_key_service_proof"`.
- **Optional fields:**
  - `standingRestrictionNotice`: string (`maxLength: 1024`).
  - `correctsRef`: `ref: {evidence: true}` — links a corrected answer issued after a seal ends.

---

## 2. Additive extensions to existing kinds (published as new definitions)

The 28 frozen baseline definitions are **never edited in place** — doing so would change their bytes and invalidate every existing `schemaRef`. Instead, each extended kind below is published as a **new definition version with a new `schemaRef`** in a `DefinitionPublished` record. Records written before this amendment continue to cite their original `schemaRef` and verify under the original definition; deployments admit both the baseline and extended definitions concurrently.

| Existing kind | Additive optional fields | Purpose |
| --- | --- | --- |
| `Deployment`, `RootsChanged`, `RootChangeApproval` | `custodyLevel` (`1 \| 2`), `witnessKeys` (`unique` array of key IDs), `overseerKey` (key ID), `approverRoles` (`unique` array of `{role: non-empty string, keys: keyId[]}`), `allowedMeasurements` (`unique` array of `^sha256:[0-9a-f]{64}$`), `sealedServiceCopies` (`unique` array of `{copyId: non-empty string, keyId: keyId}`), `hardwareAttestationRoots` (`unique` array of key IDs) | Pins the deployment contract at the registrar, binds approver roles, hardware attestation roots, and sealed key-service copy IDs to specific keys, and prevents silent level downgrades or unapproved contract changes. |
| `Endorsement` | `keyStorage` (`"hardware" \| "personal_device" \| "administered_device_file"`), `hardwareAttestationRef` (content reference `bytes:sha256:...` or `bytes:sha256+salt:...` to a cryptographically signed hardware attestation chained to a pinned hardware trust root), `signerKind` (`"personal" \| "device_session"`), `recoveryRule` (`{threshold: 1..64, recoveryKeys: keyId[]}`) | Records where a personal key is kept, distinguishes device-session keys from personal keys, and pins a person's recovery rule at first endorsement. |
| `Succession` | `recoveryRule` (`{threshold: 1..64, recoveryKeys: keyId[]}`), `recoveryProof` (see §3) | Allows a person to update their recovery rule upon valid succession and supports recovery-form succession when the old key is lost. |
| `RetentionHold`, `RetentionHoldRelease` | `basisRef` (`ref: {evidence: true}`), `reviewAt` (UTC `Z` RFC 3339 timestamp; required when `basisRef` is present on `RetentionHold`) | Binds institutional holds to a cited basis and a mandatory review date. |
| `PayloadDisposition` | `erasureAnswerRef` (`ref: {evidence: true}`), salted bytes refs in `targets` | Keeps per-session disposal unchanged and links optionally to the structured `ErasureAnswer`. |
| `Disclosure` | `releaseRequestRef` (`ref: {evidence: true}`), `releaseReceiptRef` (`ref: {evidence: true}`), salted bytes refs in `providedRefs`/`requestedRefs`/`excluding`/`policy` | Links disclosures to pre-release commitments and post-release receipts; pairs with redacted `PublishedView` for partial multi-person release. |

---

## 3. Recovery form of `Succession`

The existing `Succession` record proves continuity of a person's signing key by requiring both `predecessor` (`oldKey`) and `successor` (`newKey`) to sign. When a person loses their old key, the extended `Succession` definition accepts a second proof form:

- **Standard form (unchanged):** valid signatures by `[predecessor, successor]` in order (no `recoveryProof` present).
- **Recovery form (new):** valid signature by `[successor]` **plus** `recoveryProof`:
  - `recoveryRuleRef`: `ref: {evidence: true}` pointing to the person's active `recoveryRule` — defined as the rule registered at their earliest valid `Endorsement` or updated by their last prior **valid** `Succession` (a `recoveryRule` carried on a `Succession` takes effect only if that `Succession` itself verifies; a later institutional `Endorsement` cannot overwrite an earlier registered `recoveryRule`).
  - `approvals`: `unique: true` array (max 64 entries) of cryptographic signatures over `b"r5e-succession-recovery-v1\x00" || canonical_json({newKey: successor, oldKey: predecessor, recoveryRuleRef})` from distinct keys named in `recoveryRule.recoveryKeys`, meeting `recoveryRule.threshold`.
  - **Institution-alone prohibition:** Deployment root keys, `Endorsement` issuer keys, and keys bound to institutional `approverRoles` are **excluded institutional keys**. Even if listed in `recoveryRule.recoveryKeys`, excluded institutional keys alone can **never** satisfy `recoveryRule.threshold`: at least one verified approval MUST come from a non-institutional recovery key (`succession_institution_only_rejected`).
  - **Baseline index guard:** An unverified or failed recovery `Succession` (or standard-form A11 `Succession` with mismatched signers) MUST NOT be admitted into the baseline authority `SuccessionIndex`.

---

## 4. Salted content reference (`bytes:sha256+salt:...`)

To prevent offline guessing of short or low-entropy payloads from a bare content digest (`bytes:sha256:<hex>`), content references accept a second, salted commitment form:

- **Form:** `bytes:sha256+salt:<64 lowercase hex digest>` where `digest = sha256(b"r5e-salted-content-v1\x00" || salt || plaintext_bytes)` and `salt` is a random 32-byte per-object salt.
- **Permitted scope:** Permitted anywhere a content reference (`bytes:sha256:...` or `ref: {bytes: true}`) is permitted in A11 definitions (and in `ref: {bytes: true}` under A11 mode). Existing `bytes:sha256:<64 hex>` references remain valid and unchanged.
- **Storage invariant:** `salt` is stored **inside the encrypted content envelope, encrypted under the session key** — never in cleartext alongside the ciphertext or in database metadata. Destroying the session key destroys both the plaintext and the salt together.
- **Empty plaintext:** 0-byte plaintext (`bytes: ""`, empty base64) is valid, matching baseline `blobs`.
- **Offline verification:**
  - Carried salted content members live in the optional top-level bundle map `saltedContent: { "<bytes:sha256+salt:...>": { "salt": "<strict padded b64 32 bytes>", "bytes": "<strict padded b64 plaintext>" } }`.
  - Every carried entry in `saltedContent` (whether referenced by a record or unreferenced) MUST be recomputed once (cached by reference) and match its key digest using constant-time comparison.
  - When referenced salted content is omitted or disposed, the verifier validates the reference syntax and reports `incomplete` (`code: "salted_content_omitted"`, category `unavailable_evidence`) without leaking whether the omitted payload matched any guessed plaintext.

---

## 5. Offline verifier rules (`r5e-verify-rs` and `r5e-verify-py`)

### 5.1 Entry-point routing and baseline compatibility
- Every public entry point (CLI, file verifier, library API, and WASM) MUST automatically run A11 evaluation whenever a bundle carries any A11 record kind (`Basis`, `BasisOverlay`, `ReleaseRequest`, `ReleaseReceipt`, `ErasureAnswer`), any A11 top-level bundle member (`saltedContent`, `witnessReceipts`, `unlockLog`, `pinnedCheckpoints`), any A11 extended field (`custodyLevel`, `recoveryProof`, `hardwareAttestationRef`, `erasureAnswerRef`, `releaseRequestRef`, `releaseReceiptRef`, `recoveryRule`, `signerKind`, `keyStorage`, `basisRef`, `reviewAt`, `sealedServiceCopies`, `approverRoles`, `witnessKeys`, `overseerKey`, `allowedMeasurements`, `hardwareAttestationRoots`), or any `bytes:sha256+salt:...` reference.
- Pre-A11 baseline bundles carrying none of these execute the baseline verifier with byte-for-byte unchanged `r5e.provenance-verify-report/v2` output and strict `export.schema.json` validation (rejecting unexpected top-level keys with `malformed_bundle` when baseline-only export validation is invoked).
- Every embedded cryptographic signature check (V4, V5, V7, V8, and V4 hardware attestation) MUST verify `compute_key_id(alg, key_bytes) == signer_key_id` using constant-time comparison (`subtle::ConstantTimeEq` / `hmac.compare_digest`) before verifying the signature.

### 5.2 Complete finding classification
Every finding in an A11 report — **both baseline findings and A11 findings** — is classified into one of four categories alongside `ok` / `failed` / `incomplete`:

| Category | Baseline checks / codes | A11 checks / codes |
| --- | --- | --- |
| `cryptographic_proof` | `identity`, `signature`, `content` (when carried/verified), `epoch`, `merkle`, `membership` | `salted_content_ref` (when carried), `witness_receipt_binding`, `succession_recovery`, `erasure_l2_proof` (verified/failed L2 proof), `release_request_approvals` (signature check & cryptographically verified hardware attestation), `checkpoint_and_unlock_log` (checkpoint inclusion/monotonicity/fork) |
| `mechanical_check` | `body`, `schema`, `authority`, `start`, `seal_chain`, `publication` (when carried), `profile_bounds`, `retention`, `bundle` | `basis_signatures` (personal/workload/failures), `basis_declared_power` (power/proposal/subjects), `basis_overlay_order` (withdrawal/expiry/signer), `release_request_approvals` (role/threshold/endorsement/subjects), `release_receipt_fingerprint`, `checkpoint_and_unlock_log` (`unlock_without_release_record`, `unrecorded_plaintext_in_bundle`), `definition_coexistence` |
| `institutional_assertion` | `profile` (`profile_not_trusted`) | `basis_signatures` (`basis_person_signed_by_device_session`), `release_request_approvals` (`hardware_attestation_unverified`), `erasure_l2_proof` (Level 1 `institution_claim`) |
| `unavailable_evidence` | `content` (`content_not_carried`, `not_carried`), `publication` (`publication_not_carried`), `epoch` (`manifest_not_carried`), any baseline `incomplete` due to omitted evidence | `basis_declared_power` (`basis_ref_missing`), `basis_overlay_order` (`until_event_unverified`), `release_request_approvals` (`release_target_missing`), `witness_receipt_binding` (`witness_request_missing`), `erasure_l2_proof` (`erasure_copy_confirmation_pending`), `salted_content_ref` (`salted_content_omitted`) |

Findings are sorted deterministically by `(layer, subject, check, code, about)` (with `null` sorting before any string for `about`). The overall `verdict` is `"failed"` if any baseline OR A11 finding is `"failed"`, else `"incomplete"` if any baseline OR A11 finding is `"incomplete"`, else `"ok"`.

### 5.3 Rules V1–V11

| # | Check name | Layer | Rule | Failure / finding code | Category |
| --- | --- | --- | --- | --- | --- |
| V1 | `basis_signatures` | 2 | Using the structural person predicate (§1.1: `subjects` non-empty or `representative` present): a person-naming `Basis` must have **exactly 2** verified distinct signatures (both passing DSSE verification): one with an active `Endorsement` covering `institution` (`actsFor == institution`) and one with an active `Endorsement` covering a named `subject` or `representative` with `signerKind` in `{"personal", "device_session"}`. When `signerKind == "device_session"`, emit `ok` with `code: "basis_person_signed_by_device_session"` and category `institutional_assertion`. A non-person workload `Basis` (`subjects: []`, no `representative`) needs 1 valid signature. | `basis_missing_counter_signature`, `basis_invalid_signer_binding`, `basis_unexpected_signature_count`, `basis_person_signed_by_device_session` (`ok`, `institutional_assertion`) | `mechanical_check` / `institutional_assertion` |
| V2 | `basis_declared_power` | 3 | Applies to `ReleaseRequest`, `Disclosure` (via `releaseRequestRef` -> `ReleaseRequest` -> `Basis`), and `RetentionHold` (via `basisRef`, requiring `"hold"` power in at least one ground and requiring `reviewAt`). If `basisRef` is omitted from the bundle -> `incomplete` (`basis_ref_missing`); if it points to an `amendment_proposal` overlay -> `failed` (`proposal_authorises_nothing`); if it points to another non-`Basis` record -> `failed` (`basis_ref_wrong_kind`); if the cited `Basis` failed V1 -> `failed` (`basis_invalid`). Reject any act citing `declaredTerms`, an unknown `groundId`, or a power absent from `groundId`. Every subject of every targeted session/record MUST be in `Basis.subjects` (`basis_subjects_do_not_cover_targets`). Independent pass from V3 (does not suppress V3). `ok` sets `about: basisRef`. | `basis_ref_missing` (`incomplete`), `basis_ref_wrong_kind`, `basis_invalid`, `act_cites_declared_or_absent_power`, `proposal_authorises_nothing`, `basis_subjects_do_not_cover_targets`, `retention_hold_missing_review_at` | `mechanical_check` / `unavailable_evidence` |
| V3 | `basis_overlay_order` | 3 | Applies to `ReleaseRequest`, `Disclosure` (via `releaseRequestRef`), and `RetentionHold` (via `basisRef`). Evaluate `Basis` + `BasisOverlay` records in canonical order (at L1: same-stream `seq` takes precedence over `effectiveAt`, cross-stream `(capturedAt, ref)`; at L2: witness `logIndex` when available). Verify overlay signer authority (`withdrawal` must be signed by an active key endorsed for a named `subject`, `representative`, or `institution`; unauthorized signer -> `overlay_signer_unauthorized`). Reject acts after withdrawal or past `duration.until` (full-precision RFC 3339 instant comparison; `ReleaseRequest.timeWindow.notAfter` must not exceed `duration.until` or act `capturedAt` > `until`). For `duration.untilEvent`, reject if a matching triggering event (e.g. `SessionClosed` for `"session_closed"`) precedes the act; otherwise report `incomplete` (`until_event_unverified`). | `basis_power_withdrawn_or_expired`, `until_event_unverified` (`incomplete`), `overlay_signer_unauthorized` | `mechanical_check` / `unavailable_evidence` |
| V4 | `release_request_approvals` | 2 | Requires a valid resolved `Basis` (never `ok` if `basisRef` is missing/wrong-kind/invalid). `approvals` length must be `<= 64`. Every approval in `ReleaseRequest.approvals[]` must verify over canonical `(basisFingerprint, contractVersion, recipientKey, requestId)` with constant-time key-ID binding, come from a distinct `(signerKey, role)` whose latest valid, non-revoked, in-window `Endorsement` (ordered by `(capturedAt, seq, ref)`) carries `keyStorage: "hardware"`, belong to the cited `role` in the active contract's pinned `approverRoles` (fail closed if `approverRoles` omits the role), and distinct qualifying keys must meet `approvalRule.threshold` (compared as `i64` without 32-bit truncation). If `hardwareAttestationRef` verifies cryptographically against pinned `hardwareAttestationRoots` (§7.4) -> `ok` (`cryptographic_proof`); otherwise -> `incomplete` (`hardware_attestation_unverified`, category `institutional_assertion`). `ReleaseRequest.subjects` MUST equal the exact union of subjects across `Basis` and all resolved `targets` (a session target `urn:r5e:session:...` resolves via carried `SessionOpened` / session records and linked `Basis` records in `contextRefs` or `payload.session`; a missing target -> `incomplete`, `release_target_missing`). | `approval_signature_invalid`, `approval_key_not_hardware`, `approval_endorsement_inactive`, `approval_role_unlisted`, `approval_threshold_not_met`, `hardware_attestation_unverified` (`incomplete`), `release_subjects_incomplete`, `release_target_missing` (`incomplete`) | `cryptographic_proof` / `mechanical_check` / `institutional_assertion` / `unavailable_evidence` |
| V5 | `witness_receipt_binding` | 3 | Validate every entry in `witnessReceipts` (standalone or referenced by `ReleaseReceipt`). Deterministic check order: (1) map key equals `bytes:sha256(canonical(receipt))` (`witness_receipt_hash_mismatch`), (2) `witnessKey` is in active contract's pinned `witnessKeys` (`witness_unpinned`), (3) constant-time key-ID binding + valid signature (`witness_receipt_hash_mismatch`), (4) `requestRef` resolves to a carried `ReleaseRequest` (or `BasisOverlay` when witnessing L2 overlay ordering; missing -> `incomplete`, `witness_request_missing`; any other kind -> `failed`, `witness_request_wrong_kind`), (5) `requestHash == "sha256:" \|\| hex(sha256(request_payload_bytes))` (`witness_receipt_hash_mismatch`). Also reject any `ReleaseRequest` embedding `witnessReceiptRef`. | `witness_receipt_hash_mismatch`, `witness_unpinned`, `witness_request_wrong_kind`, `witness_request_missing` (`incomplete`) | `cryptographic_proof` / `unavailable_evidence` |
| V6 | `release_receipt_fingerprint` | 2 | Evaluate both checks independently (no short-circuiting): (1) `releasedFingerprint` MUST be present when `outcome` is `"released"` or `"delivered"` (`released_fingerprint_missing`) and MUST be absent when `outcome` is `"denied"` or `"failed"` (`released_fingerprint_unexpected`); (2) at `custodyLevel: 2` (resolved at the receipt's applicable contract version), `witnessReceiptRef` MUST be present (`witness_receipt_missing_l2`). Baseline `retention` / `content` checks exclude `ReleaseReceipt.releasedFingerprint` and `ReleaseReceipt.witnessReceiptRef` from `bundle.blobs` lookup. | `released_fingerprint_missing`, `released_fingerprint_unexpected`, `witness_receipt_missing_l2` | `mechanical_check` |
| V7 | `succession_recovery` | 2 | Applies to A11 `Succession` records. Standard form (no `recoveryProof`): requires valid signatures by `[predecessor, successor]` in order (`succession_signer_mismatch`). Recovery form (`recoveryProof` present): requires valid signature by `[successor]` (`succession_signer_mismatch`), `recoveryRuleRef` resolving to the predecessor's earliest valid `Endorsement` or prior valid `Succession` (`succession_recovery_rule_unknown`, `about: recoveryRuleRef`), `approvals` length `<= 64`, valid distinct recovery signatures with constant-time key-ID binding meeting `threshold` (`i64` comparison, `succession_recovery_threshold_not_met`), and at least one verified non-institutional recovery key (`succession_institution_only_rejected`). Failed recovery or mismatched-signer `Succession` is excluded from baseline `SuccessionIndex`. | `succession_recovery_threshold_not_met`, `succession_recovery_rule_unknown`, `succession_institution_only_rejected`, `succession_signer_mismatch` | `cryptographic_proof` |
| V8 | `erasure_l2_proof` | 3 | For each session entry in `ErasureAnswer` with `governedState: "destroyed"`: at `custodyLevel: 2`, `evidentialSupport: "institution_claim"` fails (`erasure_institution_claim_at_l2`). At `custodyLevel: 1`, `"institution_claim"` passes as `ok` (`institutional_assertion`). For `evidentialSupport: "sealed_key_service_proof"`: active contract `sealedServiceCopies` MUST be non-empty (`erasure_proof_invalid_or_missing_l2`); `proofRef` MUST be present and carried (`erasure_proof_invalid_or_missing_l2`); `copyConfirmations` MUST have no duplicate `copyId` (`erasure_proof_invalid_or_missing_l2`); every `copyId` in `confirmedCopies` MUST exist in contract `sealedServiceCopies` (`erasure_unknown_copy_id`, one finding per unknown copy) and carry a valid signature from that copy's pinned `keyId` with constant-time key-ID binding (`erasure_proof_invalid_or_missing_l2`, `about: copyId`); if all listed confirmations verify but copies in `sealedServiceCopies` remain unconfirmed, emit one `incomplete` (`erasure_copy_confirmation_pending`, `unavailable_evidence`, `about: copyId`) per missing copy. | `erasure_proof_invalid_or_missing_l2`, `erasure_unknown_copy_id`, `erasure_institution_claim_at_l2`, `erasure_copy_confirmation_pending` (`incomplete`) | `cryptographic_proof` / `institutional_assertion` / `unavailable_evidence` |
| V9 | `salted_content_ref` | 1 | Pre-verify every entry in `bundle.saltedContent` once (cached by ref): `salt` must decode to exactly 32 bytes, `bytes` must be valid strict padded base64 (empty `""` for 0-byte plaintext is valid), and `sha256(b"r5e-salted-content-v1\x00" \|\| salt \|\| plaintext)` must match the key digest in constant time (`salted_content_digest_mismatch`). Unreferenced tampered entries fail with `subject: ref`. Referenced omitted entries report `incomplete` (`salted_content_omitted`, `unavailable_evidence`, `about: ref`). | `salted_content_digest_mismatch`, `salted_content_omitted` (`incomplete`) | `cryptographic_proof` / `unavailable_evidence` |
| V10 | `checkpoint_and_unlock_log` | 3 | (a) Enforce strictly increasing `seq` over `bundle.checkpoints` and detect duplicate-`seq` forks; validate checkpoints against both reader-supplied `trustedCheckpoints` (CLI `--checkpoint` / API option) and bundle `pinnedCheckpoints` (`checkpoint_fork_or_stale`). (b) At Level 1, every `unlockLog` entry must have non-empty string `entryId` and `session` and reference a verified `ReleaseReceipt` (`released`/`delivered`) or `Disclosure` (`provided`/`partial`) whose own targets/scope cover that `session` (`unlock_without_release_record`). (c) Any carried session plaintext (in `blobs` or `saltedContent`, including unreferenced session blobs) outside the shared excluded governance kinds (`DefinitionPublished`, `Deployment`, `ChainStarted`, `RootsChanged`, `RootChangeApproval`, `Endorsement`, `Succession`, `Revocation`, `Checkpoint`, `EpochSeal`, `Basis`, `BasisOverlay`, `ReleaseRequest`, `ReleaseReceipt`, `ErasureAnswer`) must be covered by a valid `ReleaseReceipt` (`released`/`delivered`) or `Disclosure` (`provided`/`partial`, using `providedRefs` or `scope` minus `excluding`) (`unrecorded_plaintext_in_bundle`). | `checkpoint_fork_or_stale`, `unlock_without_release_record`, `unrecorded_plaintext_in_bundle` | `cryptographic_proof` / `mechanical_check` |
| V11 | `definition_coexistence` | 1 | When a bundle publishes >= 2 definitions for a kind, records citing the baseline `schemaRef` verify under the baseline definition; emits `ok` (`mechanical_check`) ONLY when the baseline `body` check actually passed for that record. | *(passes `ok` only when baseline `body` is `ok`)* | `mechanical_check` |

---

## 6. Conformance test vector cases

Conformance test vector cases live under `amendments/a11/cases/<case-name>/{bundle.json, case.json, expected-report.json}` and are generated deterministically by `amendments/a11/generate_vectors.py`. The corpus includes all 33 core cases across V1–V11 plus adversarial regression cases covering entry-point routing, definition boundaries, false-accept guards, cross-verifier parity, historical contract pinning, embedded key-ID binding, and malformed-input robustness.

---

## 7. Wire contract for offline verifiers (`r5e-verify-rs` and `r5e-verify-py`)

### 7.1 Additive top-level bundle members on `r5e.provenance-export/v2`

All four members below are **optional** in A11 mode. In strict baseline-only export validation (pre-A11 bundles), unexpected top-level keys are rejected with `malformed_bundle` per `export.schema.json` (`additionalProperties: false`). In A11 mode, both verifiers MUST validate the full inner shape of each present member (emitting `malformed_bundle` on invalid types, missing required fields, extra keys, or invalid UTC `Z` timestamps):

1. **`saltedContent`** (`object`, map from `^bytes:sha256\+salt:[0-9a-f]{64}$` to object with `additionalProperties: false`):
   ```json
   {
     "bytes:sha256+salt:<64 hex>": {
       "salt": "<strict padded base64 of 32-byte salt>",
       "bytes": "<strict padded base64 of plaintext bytes; \"\" valid for 0 bytes>"
     }
   }
   ```
   - Digest formula: `sha256(b"r5e-salted-content-v1\x00" || salt || plaintext_bytes)`.
   - `salt` MUST decode to exactly 32 bytes; `bytes` MAY be `""` (0-byte plaintext).

2. **`witnessReceipts`** (`object`, map from `^bytes:sha256:[0-9a-f]{64}$` to object with `additionalProperties: false`):
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
   - `logIndex` MUST be a non-negative integer (not float/bool); `loggedAt` MUST be a UTC `Z` RFC 3339 timestamp.
   - Map key MUST equal `"bytes:sha256:" + sha256(canonical_json(receipt_object))`.
   - `requestHash` MUST equal `"sha256:" + sha256(release_request_payload_bytes)`.

3. **`unlockLog`** (`array` of objects with `additionalProperties: false`):
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
   - `entryId` and `session` MUST be non-empty strings; `releaseRef` MUST be `null` or `^evidence:sha256:[0-9a-f]{64}$`; `unlockedAt` MUST be a UTC `Z` RFC 3339 timestamp.

4. **`pinnedCheckpoints`** (`array` of objects with `additionalProperties: false`):
   ```json
   [
     {
       "ref": "evidence:sha256:<64 hex>",
       "seq": 1
     }
   ]
   ```
   - `seq` MUST be a positive integer (`>= 1`); `ref` MUST match `^evidence:sha256:[0-9a-f]{64}$`.

### 7.2 Reader-supplied verification options (`trustedCheckpoints`)

Because `bundle.pinnedCheckpoints` lives inside the untrusted bundle, verifiers MUST also accept out-of-band reader-supplied checkpoint pins:
- **CLI:** repeatable `--checkpoint <seq>:<evidence:sha256:...>` option.
- **Library / WASM / `case.json`:** optional `trustedCheckpoints` array of `{"seq": <int >= 1>, "ref": "evidence:sha256:<64 hex>"}` objects.
- V10 validates `bundle.checkpoints` against the union of `trustedCheckpoints` and `bundle.pinnedCheckpoints`; stripping `bundle.pinnedCheckpoints` cannot evade a reader-supplied `trustedCheckpoints` pin.

### 7.3 Deployment contract wire shapes and historical resolution

On `Deployment`, `RootsChanged`, and `RootChangeApproval`:
- **`approverRoles`**: array of `{"role": "<non-empty string>", "keys": ["key:..."]}`.
- **`sealedServiceCopies`**: array of `{"copyId": "<non-empty string>", "keyId": "key:..."}`.
- **`allowedMeasurements`**: array of `"sha256:<64 hex>"`.
- **`hardwareAttestationRoots`**: optional array of `"key:..."` (pinned trust roots for hardware attestation verification).
- **Historical contract state:** Verifiers MUST sort authenticated start-stream records (`Deployment`, `RootsChanged`) in ascending `(seq, ref)` order (never bundle array order), accumulate inherited fields across partial `RootsChanged` updates, and resolve each act against the contract version pinned by `contractVersion` (or active at the act's capture/stream position when `contractVersion` is absent). A later downgrade to `custodyLevel: 1` MUST NOT exempt an earlier Level 2 `ReleaseReceipt` from `witnessReceiptRef`.

### 7.4 Canonical signing inputs for embedded A11 proofs

All embedded signatures use the key's registered algorithm (Ed25519 / ES256 / ES384) over domain-separated canonical JSON (RFC 8785 / Core C1). Before verifying any embedded signature, the verifier MUST look up the key in `bundle.keys` and verify `compute_key_id(alg, key_bytes) == key_id` using constant-time comparison.

- **V4 Release approval (`ReleaseRequest.approvals[i].signature`):**
  `b"r5e-release-approval-v1\x00" || canonical_json({ "basisFingerprint": basisRef, "contractVersion": contractVersion, "recipientKey": recipientKey, "requestId": requestId })`

- **V4 Hardware attestation (`Endorsement.hardwareAttestationRef` blob or salted content):**
  Canonical JSON object (`additionalProperties: false`):
  ```json
  {
    "attestedAt": "2026-11-22T11:02:30Z",
    "device": "hsm-01",
    "keyId": "key:ed25519:sha256:<64 hex>",
    "rootKeyId": "key:ed25519:sha256:<64 hex>",
    "signature": "<strict padded base64>"
  }
  ```
  - `rootKeyId` MUST be in the active contract's `hardwareAttestationRoots` (or deployment `roots[].key` if `hardwareAttestationRoots` is omitted).
  - `keyId` MUST equal the endorsed approver's `subject` key ID.
  - `attestedAt` MUST be a UTC `Z` RFC 3339 timestamp.
  - `signature` is a cryptographic signature by `rootKeyId` over:
    `b"r5e-hw-attestation-v1\x00" || canonical_json({ "attestedAt": attestedAt, "device": device, "keyId": keyId, "rootKeyId": rootKeyId })`.
  - If `hardwareAttestationRef` is missing, uncarried, unsigned, malformed, or fails verification, V4 MUST emit `incomplete` (`code: "hardware_attestation_unverified"`, `category: "institutional_assertion"`).

- **V5 Witness receipt (`witnessReceipts[ref].signature`):**
  `b"r5e-witness-receipt-v1\x00" || canonical_json({ "logIndex": logIndex, "loggedAt": loggedAt, "requestHash": requestHash, "requestRef": requestRef, "witnessKey": witnessKey })`

- **V7 Succession recovery (`Succession.recoveryProof.approvals[i].signature`):**
  `b"r5e-succession-recovery-v1\x00" || canonical_json({ "newKey": successor, "oldKey": predecessor, "recoveryRuleRef": recoveryRuleRef })`

- **V8 Level 2 erasure proof (`ErasureAnswer.sessions[i].proofRef` blob or salted content):**
  Canonical JSON object:
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
  `b"r5e-erasure-proof-v1\x00" || canonical_json({ "copyId": copyId, "destroyedAt": destroyedAt, "session": session })`, signed by the `keyId` bound to `copyId` in the active contract's `sealedServiceCopies`.

### 7.5 Variable-signature rule for A11 kinds

Baseline `r5e.kind-definition/v1` stores a single integer `signatures`. For the four A11 kinds whose valid signature count depends on record semantics, the definition declares `"signatures": 1` and verifiers apply:

- `provenance.r5e.io/v2/Basis`: 1 or 2 signatures (enforced by V1).
- `provenance.r5e.io/v2/BasisOverlay`: 1 or 2 signatures.
- `provenance.r5e.io/v2/ReleaseRequest`: `>= 1` signatures.
- `provenance.r5e.io/v2/Succession` (A11 extended definition): 2 signatures `[predecessor, successor]` in order (standard form, no `recoveryProof`) OR 1 signature `[successor]` (recovery form, with `recoveryProof`, enforced by V7).

### 7.6 Canonical `A11Report` JSON shape and vector expectation format

Both `r5e-verify-rs` and `r5e-verify-py` emit the same canonical A11 report JSON structure:

```json
{
  "format": "r5e.provenance-verify-report/v2",
  "amendment": "A11",
  "verdict": "ok | failed | incomplete",
  "summary": {
    "ok": 0,
    "failed": 0,
    "incomplete": 0,
    "total": 0
  },
  "categories": {
    "cryptographic_proof": 0,
    "mechanical_check": 0,
    "institutional_assertion": 0,
    "unavailable_evidence": 0
  },
  "baseline": {
    "findings": [
      {
        "about": null,
        "category": "cryptographic_proof | mechanical_check | institutional_assertion | unavailable_evidence",
        "check": "<baseline check name>",
        "code": "<baseline code>",
        "layer": 1,
        "result": "ok | failed | incomplete",
        "subject": "<ref or bundle>"
      }
    ],
    "summary": {
      "ok": 0,
      "failed": 0,
      "incomplete": 0,
      "total": 0
    }
  },
  "a11Findings": [
    {
      "about": "<optional string or null>",
      "category": "cryptographic_proof | mechanical_check | institutional_assertion | unavailable_evidence",
      "check": "<V1..V11 check name>",
      "code": "<ok or finding code from §5>",
      "layer": 1,
      "result": "ok | failed | incomplete",
      "subject": "<evidence:sha256:... or bytes:sha256+salt:... or bundle>"
    }
  ]
}
```

- `summary` aggregates counts across **both** `baseline.findings` and `a11Findings`.
- `categories` aggregates counts across **both** `baseline.findings` and `a11Findings`.
- `a11Findings` is sorted deterministically by `(layer, subject, check, code, about)` (with `null` before strings).
- `verdict` is `"failed"` if `summary.failed > 0`, else `"incomplete"` if `summary.incomplete > 0`, else `"ok"`.

Each `case.json` under `amendments/a11/cases/<case-name>/` carries:
- `name`, `description`
- `trustedChain`, `trustedRoots`, `trustedPublishers`, `trustedProfiles`, `minStartSeq`
- optional `trustedCheckpoints` (array of `{"seq", "ref"}` for reader-supplied V10 pins)
- optional `mode` (`"a11"` default, or `"baseline"` for strict pre-A11 export checks).

Each `expected-report.json` under `amendments/a11/cases/<case-name>/` specifies:
- `format`: `"r5e.provenance-verify-report/v2"`
- `amendment`: `"A11"`
- `verdict`: `"ok" | "failed" | "incomplete"`
- `baselineClean`: `true` if `baseline.summary.failed == 0` AND `baseline.summary.incomplete == 0`, else `false`
- `expectedA11Findings`: exact sorted list of expected A11 findings for that vector case (including `about` and `category`).
