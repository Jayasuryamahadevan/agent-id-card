# AIC — Agent ID Card Specification, v1.0

**Status:** normative for this repository. Any implementation, in any
language or runtime, that produces and verifies the exact JSON shapes and
follows the exact procedures in this document is a conformant AIC
implementation — conformance does not depend on this repository's Python
code in any way.

## 0. Why this document is the spec, not the code

An autonomous agent's runtime might be Python, Node, Go, Rust, C++ on a
microcontroller, or something that does not exist yet. It might have no
Python interpreter available at all. If "the ID card format" only lived
as a Python library, every other ecosystem would be locked out, and the
format would really be "however that one library happens to serialize
things" rather than an actual protocol. So the source of truth is this
document: exact JSON, exact byte-level signing procedure, exact
algorithms, described independently of any programming language. A
reference implementation may exist alongside this document (see
`agent_id_card/` in this repository) for convenience, but if it and this
document ever disagree, **this document is correct and the code has a
bug.**

Everything below uses [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt)
keywords (MUST, SHOULD, MAY) normatively.

## 1. Design principles

1. **A card is a lineage, not a photo.** An agent is forked, upgraded,
   re-keyed, and retired over its life. AIC models identity as an
   append-only, hash-chained sequence of **epochs**, not one static,
   long-lived credential.
2. **Liveness is cheap and separate from identity.** Renewing is a tiny,
   frequent, near-free signed heartbeat. Default credential validity is
   short. There is no central revocation list for the ordinary case of
   "this agent no longer exists" — it simply stops renewing.
3. **Trust is a web, not a single certificate authority.** Any party —
   an operator, a model provider, a peer agent, a human auditor — can
   independently attach a signed **attestation** to an agent's identity
   without needing anyone's permission and without invalidating anyone
   else's attestation.
4. **Delegation narrows, and narrowing is enforced at minting time, not
   merely checked later.** A short-lived sub-identity can never claim
   more authority than its parent, and this is a property of how the
   delegate card is constructed, not a rule a downstream verifier has to
   remember to apply.
5. **The card MUST NOT lie, and MUST NOT be marketing copy.** Every
   field is either (a) independently cryptographically checkable, or (b)
   explicitly and visibly a self-declared, unverified claim. There is no
   field for subjective superlatives. See §6 for the normative rules
   this implies.
6. **Disclosure is tiered and privilege-gated, but every tier is
   independently honest.** A card has three tiers of increasing
   sensitivity (§5). Which tier a given verifier receives is a policy
   decision made by whoever holds the identity, not something this
   specification enforces in transport — but every tier, once disclosed,
   is fully and independently verifiable, and a mismatch between what a
   lower tier claims and what a higher tier actually contains is
   cryptographically detectable, never just asserted.

## 2. Cryptographic primitives (implementation-agnostic)

| Primitive | Choice | Notes |
|---|---|---|
| Signature algorithm | Ed25519 (RFC 8032) | 32-byte public key, 64-byte signature. Every mainstream language has a maintained implementation. |
| Canonicalization | RFC 8785 JSON Canonicalization Scheme (JCS) | Deterministic, unique byte string for any JSON value. This is what actually gets signed. |
| Digest | SHA-256 | Written as `"sha256:" + lowercase-hex(digest)`, e.g. `"sha256:9f3a2b..."`. |
| Binary encoding | base64url, **no padding** (RFC 4648 §5) | Used for public keys, signature values, private key export. |

### 2.1 `agent_id` derivation

```
agent_id = "aic:agent:" + base64url( SHA-256( raw 32-byte Ed25519 public key ) )
```

This is self-certifying: anyone holding a public key can recompute the
`agent_id` themselves. No external authority assigns it.

### 2.2 Signing procedure

To sign a JSON object `record`:

1. Remove the top-level keys `signature` and `predecessor_signature` if
   present (an object is never signed over its own signature block).
2. Canonicalize the remaining object per RFC 8785. This produces an
   exact UTF-8 byte string.
3. Sign those bytes with Ed25519.
4. Attach: `"signature": {"alg": "Ed25519", "value": base64url(signature bytes)}`.

To verify: perform steps 1–2 identically on the received object, then
Ed25519-verify the `signature.value` bytes against the given public key
and those canonical bytes. **A verifier MUST reject any object whose
`alg` is not exactly `"Ed25519"`** (no algorithm negotiation — a single,
unambiguous, modern choice, matching this format's "does not lie" ethos:
no downgrade path to a weaker algorithm to be silently accepted).

### 2.3 Timestamps

All timestamps are UTC, millisecond precision, formatted
`YYYY-MM-DDTHH:MM:SS.sssZ` (e.g. `2026-08-31T12:00:00.000Z`). String
comparison and chronological comparison agree for this format.

## 3. The epoch chain (Tier 1 — public)

An **epoch** is one version of an agent's core identity content. Epochs
are hash-chained: each one (after the first) references the exact
signed bytes of the one before it, so the full lineage is tamper-evident
end to end.

> The `public_key`, digest, and signature VALUES in every example from
> here through §9 are illustrative placeholders chosen for readability,
> not real cryptographic output — they do not verify against each other.
> **Appendix A** gives a complete, real, independently-reproducible
> worked example (fixed test-only private keys, genuine Ed25519
> signatures, genuine SHA-256 digests, every cross-reference checked) —
> use it to validate a new implementation against this specification.

### 3.1 Genesis epoch

```json
{
  "aic": "1.0",
  "type": "epoch",
  "agent_id": "aic:agent:hVOSG0QR-m5-HjlgLHd5MJMbObVOVZmS4Prbz96X2Pg",
  "epoch_number": 0,
  "transition": "genesis",
  "prior_epoch_digest": null,
  "public_key": "3Zwt9lqe3JvJwPXfN0h1sHkH1r5Kx1Q2G8V2XyZ4b5c",
  "display_name": "warehouse-picker-07",
  "purpose": "Picks and packs warehouse orders in aisles 3-9; reports pick status to the WMS.",
  "capability_categories": ["actuate", "observe"],
  "detailed_digest": "sha256:9f3a2bcb6f1e4a7d0c8e5f2a1b3c4d5e6f7089ab1234cdef5678901234abcdef",
  "sensitive_digest": "sha256:1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6978012345abcdef6789012345bcdef01",
  "issued_at": "2026-08-31T12:00:00.000Z",
  "signature": {"alg": "Ed25519", "value": "MEUCIQ...base64url..."}
}
```

Required fields: `aic`, `type` (`"epoch"`), `agent_id`, `epoch_number`
(`0`), `transition` (`"genesis"`), `prior_epoch_digest` (`null`),
`public_key`, `display_name`, `purpose`, `capability_categories`,
`detailed_digest`, `issued_at`, `signature`. `sensitive_digest` is
`null` if this agent has no Tier 3 content (rare — see §6.3).

- `display_name` and `purpose` MUST be factual and falsifiable (§6.1).
- `capability_categories` is a sorted, de-duplicated list of the
  substring before the first `.` of every capability ID in this epoch's
  Tier 2 `declared_capabilities` (e.g. `["actuate.motors.forklift.v2",
  "observe.inventory.scan.v1"]` → `["actuate", "observe"]`). It MUST be
  computed mechanically from Tier 2 content, **never** independently
  hand-declared — see §5.4 for why.
- `detailed_digest` / `sensitive_digest` are `"sha256:" + digest-of-Tier-2/3-content`
  as defined in §5.

### 3.2 Successor epochs: `capability_update`

Minted by the same key, when purpose or capabilities change but the key
does not:

```json
{
  "aic": "1.0",
  "type": "epoch",
  "agent_id": "aic:agent:hVOSG0QR-m5-HjlgLHd5MJMbObVOVZmS4Prbz96X2Pg",
  "epoch_number": 1,
  "transition": "capability_update",
  "prior_epoch_digest": "sha256:7788...",
  "public_key": "3Zwt9lqe3JvJwPXfN0h1sHkH1r5Kx1Q2G8V2XyZ4b5c",
  "display_name": "warehouse-picker-07",
  "purpose": "Picks and packs warehouse orders in aisles 3-9; reports pick status to the WMS.",
  "capability_categories": ["actuate", "observe", "coordinate"],
  "detailed_digest": "sha256:aa11...",
  "sensitive_digest": "sha256:1c2b...",
  "issued_at": "2026-09-14T08:30:00.000Z",
  "signature": {"alg": "Ed25519", "value": "..."}
}
```

`public_key` MUST be identical to the prior epoch's. `prior_epoch_digest`
MUST equal `"sha256:" + digest(canonicalize(prior_epoch))` — the digest
is computed over the prior epoch **including its own signature**, so it
pins one exact, already-issued object, not merely its unsigned content.

### 3.3 Successor epochs: `key_rotation`

Minted when the active key changes (scheduled rotation, or suspected
compromise recovery):

```json
{
  "aic": "1.0",
  "type": "epoch",
  "agent_id": "aic:agent:hVOSG0QR-m5-HjlgLHd5MJMbObVOVZmS4Prbz96X2Pg",
  "epoch_number": 2,
  "transition": "key_rotation",
  "prior_epoch_digest": "sha256:aa11...",
  "public_key": "9pQr2StUvWxYz1AbCdEfGhIjKlMnOpQrStUvWxYzAbC",
  "display_name": "warehouse-picker-07",
  "purpose": "Picks and packs warehouse orders in aisles 3-9; reports pick status to the WMS.",
  "capability_categories": ["actuate", "observe", "coordinate"],
  "detailed_digest": "sha256:bb22...",
  "sensitive_digest": "sha256:cc33...",
  "issued_at": "2026-10-01T00:00:00.000Z",
  "signature": {"alg": "Ed25519", "value": "<signed by the NEW key>"},
  "predecessor_signature": {"alg": "Ed25519", "value": "<the SAME canonical bytes, signed by the OLD key>"}
}
```

`agent_id` MUST remain identical across every rotation — it was fixed at
genesis and is never recomputed from a later key. This epoch carries
**two** signatures over identical canonical bytes: `signature` (from the
new key, proving the new key is real and controlled by whoever is
minting this epoch) and `predecessor_signature` (from the *prior*
epoch's key, proving the entity that controlled the OLD key endorses
this new key as its legitimate successor).

**A verifier MUST reject a `key_rotation` epoch that lacks a valid
`predecessor_signature` from the exact prior epoch's `public_key`.**
Without this rule, anyone who has ever seen an agent's chain (which is
meant to be freely shareable) could mint a plausible-looking "next
epoch" under their own key — a hash link alone proves ordering, never
continuity of control.

### 3.4 Chain verification algorithm

Given a chain `[epoch_0, epoch_1, ..., epoch_n]`:

1. `epoch_0.epoch_number == 0`, `epoch_0.transition == "genesis"`,
   `epoch_0.prior_epoch_digest == null`. Verify `epoch_0.signature`
   against `epoch_0.public_key`.
2. For `i` from `1` to `n`:
   a. `epoch_i.epoch_number == epoch_{i-1}.epoch_number + 1`.
   b. `epoch_i.agent_id == epoch_{i-1}.agent_id`.
   c. `epoch_i.prior_epoch_digest == "sha256:" + digest(canonicalize(epoch_{i-1}))`.
   d. If `epoch_i.transition == "key_rotation"`: verify
      `epoch_i.predecessor_signature` against `epoch_{i-1}.public_key`,
      and `epoch_i.public_key` MAY differ from `epoch_{i-1}.public_key`.
      Otherwise: `epoch_i.public_key == epoch_{i-1}.public_key` MUST
      hold (any key change outside a declared `key_rotation` transition
      is a fatal error).
   e. Verify `epoch_i.signature` against `epoch_i.public_key`.
3. If every step passes, the chain is valid and `epoch_n` is the
   **current epoch**.

Any failure at any link MUST fail verification of the *entire* chain —
there is no notion of "valid up to here, then who knows."

## 4. Renewal — the liveness heartbeat

```json
{
  "aic": "1.0",
  "type": "renewal",
  "agent_id": "aic:agent:hVOSG0QR-m5-HjlgLHd5MJMbObVOVZmS4Prbz96X2Pg",
  "epoch_digest": "sha256:cc33...",
  "renewed_at": "2026-10-01T00:00:00.000Z",
  "valid_until": "2026-10-02T00:00:00.000Z",
  "signature": {"alg": "Ed25519", "value": "..."}
}
```

`epoch_digest` pins the exact current epoch this renewal is for.
Default validity SHOULD be **24 hours**; implementations MUST NOT issue
a renewal with validity greater than **7 days**. A verifier requiring
strong liveness assurance MAY additionally require `renewed_at` to be
within the last few minutes, not merely `valid_until` being in the
future.

**This is the mechanism that replaces a certificate revocation list for
the ordinary case.** A compromised, decommissioned, or crashed agent
simply stops renewing; every consumer's next liveness check fails
without needing to consult any external list. Explicit, immediate
distrust (not waiting for expiry) is what a `revocation` attestation
(§5 below is Tier content; revocation is defined here in §5.2... see
also this section's sibling, attestations, §5.2) is for.

## 5. The three disclosure tiers

An epoch's Tier 1 fields are always signed and always disclosable. Tiers
2 and 3 are **separate signed objects**, referenced by the epoch through
a SHA-256 digest commitment rather than embedded inline. This is the
mechanism that makes privilege-gated disclosure honest instead of merely
"we didn't happen to send that field this time":

- A verifier who receives ONLY the epoch already knows Tier 2/3 content
  **exists** and is cryptographically bound to this exact identity and
  this exact epoch — without being able to read it.
- Once Tier 2 and/or Tier 3 content is later disclosed (by whatever
  policy the issuer applies — see §5.5), the verifier checks it against
  the digest already committed at signing time. **It can never be
  swapped for something more flattering after the fact.**
- Tier 1's own `capability_categories` field is mechanically derived
  from Tier 2's `declared_capabilities` (§3.1). A verifier who is later
  shown Tier 2 MUST recompute the categories and compare — a mismatch
  means the epoch's Tier 1 summary was dishonest, and this is
  independently detectable, not merely alleged.

### 5.1 Tier 1 — Public

Already fully specified in §3: `display_name`, `purpose`,
`capability_categories`. Suitable to hand to anyone, including an
unauthenticated party — "roughly what am I talking to."

### 5.2 Tier 2 — Detailed (`tier2_detail`)

```json
{
  "aic": "1.0",
  "type": "tier2_detail",
  "agent_id": "aic:agent:hVOSG0QR-m5-HjlgLHd5MJMbObVOVZmS4Prbz96X2Pg",
  "epoch_number": 0,
  "declared_capabilities": [
    "actuate.motors.forklift.v2",
    "observe.inventory.scan.v1"
  ],
  "operator": {
    "organization": "Acme Logistics",
    "contact": "fleet-ops@acme.example",
    "jurisdiction": "US-CA"
  },
  "protocols": ["fasp/1.0"],
  "issued_at": "2026-08-31T12:00:00.000Z",
  "signature": {"alg": "Ed25519", "value": "..."}
}
```

Signed by the same active key as the epoch it belongs to
(`agent_id`+`epoch_number` pin it to one exact epoch). "These are things
it has" — the exact capability list, who is accountable for running it,
and which agent-to-agent protocol(s) it speaks. Verification: check
`digest(canonicalize(tier2_detail)) == epoch.detailed_digest`,
`tier2_detail.agent_id == epoch.agent_id`,
`tier2_detail.epoch_number == epoch.epoch_number`, then verify its
signature against `epoch.public_key`, then recompute and compare
`capability_categories` as described above.

An implementation MAY include an optional `known_limitations` field: an
array of short, factual strings describing what this agent explicitly
cannot do (no persistent memory across sessions, no network access, a
bounded context window, sandbox restrictions, and similarly concrete
constraints). It is additive and optional — its absence does not make an
otherwise-valid `tier2_detail` object non-conformant — but an agent that
knows its own limitations SHOULD state them here rather than nowhere.
See HARNESS_BOOTSTRAP.md for a concrete procedure (aimed specifically at
an AI coding-agent harness) that populates this field honestly.

### 5.3 Tier 3 — Sensitive (`tier3_sensitive`)

```json
{
  "aic": "1.0",
  "type": "tier3_sensitive",
  "agent_id": "aic:agent:hVOSG0QR-m5-HjlgLHd5MJMbObVOVZmS4Prbz96X2Pg",
  "epoch_number": 0,
  "model_name": "acme-picker-policy",
  "model_version": "4.2.1",
  "weights_digest": "sha256:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
  "base_model": "acme-picker-policy-3.9.0",
  "hardware": {
    "accelerator": "NVIDIA Jetson Orin NX",
    "accelerator_driver_version": "540.4.0",
    "firmware_version": "R36.3",
    "cpu": "ARM Cortex-A78AE",
    "os": "Linux",
    "os_version": "5.15.148-tegra"
  },
  "software_stack": {
    "runtime": "cpython",
    "runtime_version": "3.11.9",
    "library_versions": {"torch": "2.3.1", "onnxruntime-gpu": "1.18.0"}
  },
  "build_reference": "git:8f4c2ab@ci-run-40213",
  "issued_at": "2026-08-31T12:00:00.000Z",
  "signature": {"alg": "Ed25519", "value": "..."}
}
```

This is the tier that answers "what, *exactly*, am I trusting" — real
enough to matter for an incident investigation or a security audit, and
sensitive enough that it should not be handed to just anyone (version
strings are reconnaissance data for an attacker).

**Normative rule on honesty (implements §1.5/§6):** every field here
MUST be populated by actually introspecting the running system that
issues it (see §7 for the required procedure), not hand-typed from
memory or copied from documentation. **A field whose true value genuinely
cannot be determined on this platform MUST be set to the literal string
`"unknown"` — it MUST NOT be omitted.** An absent key is indistinguishable
from "we forgot to check"; an explicit `"unknown"` is honest about the
actual epistemic state and is itself falsifiable by a verifier who
happens to know better.

Verification mirrors Tier 2: digest match against `epoch.sensitive_digest`,
agent_id/epoch_number match, signature against `epoch.public_key`.

### 5.4 Why the epoch never embeds Tier 2/3 directly

If Tier 2/3 fields lived inside the same signed epoch object, there
would be no way to disclose Tier 1 alone without either (a) breaking the
signature (since the signed bytes would now be missing fields), or (b)
requiring a completely different signature scheme (e.g. Merkle trees or
BBS+ selective-disclosure signatures). The digest-commitment design gets
nearly all of the practical benefit — provable existence and binding of
undisclosed content, tamper-evident once-disclosed content — using only
a hash function and a single ordinary signature scheme any language can
already do.

### 5.5 Recommended (non-normative) disclosure policy

This specification does not mandate a transport or access-control
mechanism — that is the surrounding agent protocol's job (FASP's paired-
peer + grant model is one example; a plain mutual-TLS client certificate
check is another). A reasonable default, absent a more specific policy:

| Tier | Default recipient |
|---|---|
| 1 | anyone, including unauthenticated discovery |
| 2 | any authenticated/paired counterpart |
| 3 | only a counterpart holding a specific audit/compliance grant, or a human operator with direct access |

A bundle (§6) MUST self-declare which tiers it actually contains via
`disclosed_tiers`, so a verifier never has to guess whether an absent
tier means "not authorized for you" or "does not exist."

## 6. Honesty and anti-hype rules (normative)

1. `display_name` and `purpose` MUST be literal, falsifiable
   descriptions of function ("picks and packs warehouse orders in
   aisles 3-9"), and MUST NOT contain unverifiable superlative or
   marketing language ("revolutionary," "best-in-class,"
   "industry-leading," "state-of-the-art," "world's most advanced," and
   equivalents in any language are all non-conformant).
2. `declared_capabilities` MUST list capabilities the agent's operator
   is prepared to have exercised and held accountable for right now —
   not aspirational or roadmap capabilities.
3. Tier 3 fields MUST reflect the actual running system (§5.3, §7), not
   a static description of "the model this line of product usually
   ships."
4. Cryptography here proves **who said something** and **that it was
   not altered after signing.** It does NOT prove that a self-declared
   claim is objectively true. `purpose`, `declared_capabilities`, and
   every Tier 3 field are self-attestations by the epoch's own key —
   only `attestation` objects (§4's sibling, formally introduced next)
   carry an independent second party's word, and even those are only as
   trustworthy as the issuer a verifier chooses to trust. **An
   implementation or accompanying document MUST NOT claim this format
   makes an agent's self-description true — only that it makes the
   self-description attributable, tamper-evident, and falsifiable.**

## 7. Attestations — independent third-party claims

```json
{
  "aic": "1.0",
  "type": "attestation",
  "subject_agent_id": "aic:agent:hVOSG0QR-m5-HjlgLHd5MJMbObVOVZmS4Prbz96X2Pg",
  "subject_epoch_digest": null,
  "kind": "operator",
  "issuer_id": "aic:agent:PqRsTuVwXyZ1AbCdEfGhIjKlMnOpQrStUvWxYzAbCd",
  "issuer_public_key": "PqRsTuVwXyZ1AbCdEfGhIjKlMnOpQrStUvWxYzAbCd",
  "claim": {"organization": "Acme Logistics", "confirmed_via": "notarized operator agreement #4471"},
  "issued_at": "2026-08-31T12:05:00.000Z",
  "expires_at": null,
  "signature": {"alg": "Ed25519", "value": "..."}
}
```

`subject_epoch_digest` is nullable: `null` means this claim applies to
the `agent_id` regardless of which epoch is current (appropriate for a
slowly-changing fact like who operates it); a non-null value pins it to
one exact epoch (appropriate for "I benchmarked epoch #3's declared
capabilities and confirm they're accurate," which stops applying once a
newer epoch supersedes it — it must be re-issued if still true).

**Well-known `kind` values** (unknown kinds MUST be treated as
informational, never rejected as invalid — new kinds are meant to be
addable without revising this document):

- `operator` — who is accountable for running this agent.
- `provenance` — an independent claim about what this agent is built
  from, distinct from (and potentially corroborating or disputing) its
  own self-declared Tier 3 content.
- `endorsement` — a free-form positive claim from a peer, auditor, or user.
- `incident` — a negative/cautionary claim. **MUST NOT be deleted once
  issued** — a bad record is appended to, never erased. An implementation
  MAY mark an incident superseded via a newer attestation, but MUST NOT
  provide any mechanism to remove a previously-disclosed incident
  attestation from history.
- `revocation` — "distrust `subject_agent_id` immediately, regardless of
  any currently-valid renewal." Almost always agent-level
  (`subject_epoch_digest: null`), since a compromised entity should not
  become trusted again merely by rotating keys. **Which issuers'
  revocation attestations a verifier honors is a local trust decision**
  (this spec does not mandate a single revocation authority) — but an
  implementation MUST support at least "any issuer I explicitly trust
  for this purpose," and SHOULD warn if it falls back to "any
  syntactically valid revocation, from any issuer" (permissive, but easy
  to abuse).

Verification: schema fields present; `issuer_public_key` really does
derive `issuer_id` (§2.1); if `subject_epoch_digest` is non-null, it
matches some epoch actually in the chain being checked (not necessarily
the current tip — a historical claim about an older epoch remains
checkable after later epochs supersede it); signature verifies against
`issuer_public_key`; not expired.

## 8. Delegate cards — short-lived, narrowed sub-identities

```json
{
  "aic": "1.0",
  "type": "delegate",
  "parent_agent_id": "aic:agent:hVOSG0QR-m5-HjlgLHd5MJMbObVOVZmS4Prbz96X2Pg",
  "parent_epoch_digest": "sha256:cc33...",
  "delegate_public_key": "ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLlKkJjIiHhGgFf",
  "scope_capability_prefixes": ["observe.inventory."],
  "purpose": "one aisle-7 cycle count",
  "max_actions": 50,
  "issued_at": "2026-08-31T13:00:00.000Z",
  "valid_until": "2026-08-31T13:30:00.000Z",
  "signature": {"alg": "Ed25519", "value": "<signed by the PARENT epoch's key>"}
}
```

`scope_capability_prefixes` MUST be a prefix-wise narrowing of the
parent's Tier 2 `declared_capabilities` — every scope prefix MUST start
with at least one of the parent's declared capability strings.
**Implementations MUST enforce this at minting time** (refuse to
construct a widening delegate at all), not merely leave it to a later
verifier to notice. Default validity SHOULD be short; implementations
MUST NOT mint a delegate valid for more than **12 hours**.

The delegate's own outgoing messages are signed by `delegate_public_key`'s
private key — this object is the grant that makes that key's authority
independently checkable, not the channel the delegate uses to speak.

## 9. The bundle — the one object actually exchanged

```json
{
  "aic": "1.0",
  "type": "bundle",
  "disclosed_tiers": [1, 2],
  "epoch_chain": [{ "epoch_number": 0, "...": "the full epoch object from §3.1, genesis through current" }],
  "detail": { "...": "the full tier2_detail object from §5.2, present because 2 is in disclosed_tiers" },
  "sensitive": null,
  "renewal": { "...": "the full renewal object from §4, or null if liveness is not being asserted" },
  "attestations": [{ "...": "zero or more full attestation objects from §7" }],
  "delegate": null
}
```

`disclosed_tiers` MUST precisely match which of `detail`/`sensitive` are
actually present (`2 ∈ disclosed_tiers ⟺ detail != null`, and likewise
for `3`/`sensitive`) — a bundle that claims a tier is disclosed but omits
its content, or vice versa, MUST be rejected as malformed.

## 10. Full verification algorithm

Given a bundle and the current time:

1. Verify the epoch chain (§3.4). If invalid, stop: `ok = false`.
2. Let `current_epoch` be the chain's last element.
3. If `disclosed_tiers` includes `2`: verify `detail` against
   `current_epoch` (§5.2), including the `capability_categories`
   cross-check.
4. If `disclosed_tiers` includes `3`: verify `sensitive` against
   `current_epoch` (§5.3).
5. If `renewal` is present, verify it (§4) against `current_epoch`;
   otherwise, liveness is unknown/false. A verifier requiring liveness
   MUST treat a missing or invalid renewal as `ok = false`; a verifier
   only checking historical chain integrity MAY proceed without one.
6. For each attestation: verify it (§7). Track which ones are valid, and
   whether any valid, trusted `revocation` attestation exists — if so,
   `ok = false` regardless of every other check.
7. If `delegate` is present, verify it (§8) against `current_epoch`.
8. `ok` is true only if: the chain is valid, AND liveness holds (or was
   not required), AND no trusted revocation is in force, AND (if
   present) the delegate is valid.

A conformant verifier SHOULD surface *why* verification failed (which
specific step, on which specific object) rather than only a bare
boolean — an operator or an upstream agent deciding what to do next
needs to know whether the problem is "expired," "revoked," "tampered,"
or "malformed," since the correct response differs for each.

## 11. Bootstrap procedure for an autonomous agent (normative)

Any agent implementing AIC MUST follow this procedure, regardless of
implementation language. See [HARNESS_BOOTSTRAP.md](HARNESS_BOOTSTRAP.md)
for this same procedure written out concretely for the specific,
common case of an AI coding-agent harness (Claude Code, OpenCode, or
similar) bootstrapping itself inside a new workspace — including the
environment-discovery checklist and the append-only action log this
document's steps below only summarize.

1. **On startup, check local persistent state for an existing epoch
   chain.**
2. **If no chain exists (first run):**
   1. Generate a new Ed25519 keypair. Persist the private key with
      owner-only file permissions (or your platform's equivalent); it
      MUST NOT be logged, transmitted, or included in any card object.
   2. Derive `agent_id` (§2.1).
   3. Collect Tier 3 content by **directly introspecting the actual
      running system** (§5.3, §6): OS, CPU, accelerator + driver
      version, runtime version, and the actual installed versions of
      whatever libraries constitute this agent's real dependency stack.
      Do not hand-type values you have not just checked. Any field you
      cannot determine MUST be `"unknown"`.
   4. Build Tier 2 content declaring the capabilities this agent's
      operator is actually prepared to stand behind right now.
   5. Compute `detailed_digest`/`sensitive_digest`, build and self-sign
      the genesis epoch (§3.1).
   6. Immediately issue a renewal (§4).
   7. Persist the chain, Tier 2 content, Tier 3 content, and renewal.
3. **If a chain already exists:**
   1. Load and verify it end to end (§3.4) before trusting any of it.
   2. If the stored renewal is missing, expired, or about to expire,
      issue a fresh one before doing anything else that depends on this
      agent's identity being currently live.
4. **On any change to purpose or declared capabilities:** mint a new
   `capability_update` epoch (§3.2). Never mutate a previously-issued
   epoch in place.
5. **On scheduled or compromise-driven key rotation:** mint a
   `key_rotation` epoch (§3.3) signed by both the old and new keys. On
   *suspected compromise* specifically, additionally request (or, if
   self-operated, issue) a `revocation` attestation (§7) against the
   prior state from a trusted operator identity — do not rely on the
   rotation alone, since a rotation only proves a new key exists, not
   that the old one should be actively distrusted going forward.
6. **Before delegating any sub-task to an ephemeral worker, tool call,
   or sub-agent:** mint a delegate card (§8) scoped to only what that
   specific sub-task needs, with the shortest validity that task can
   plausibly need — never reuse the parent's own key for a sub-task.

## 12. Security and privacy considerations

- **Tier 3 content is a fingerprinting and reconnaissance surface.**
  Exact driver/firmware versions can reveal known-vulnerable
  configurations. This is exactly why it is a separate, digest-committed
  object rather than public Tier 1 content — treat its disclosure with
  the same care as a vulnerability-scan result.
- **A relay or transport MUST NOT be treated as an authorization
  authority.** Signatures and the tier digest commitments must be
  checked by the verifying party itself; a relay that merely forwarded a
  bundle proves nothing about its content.
- **Renewal, not revocation lists, is the default liveness mechanism** —
  design any storage or caching layer around "the last known renewal for
  this agent_id," not around fetching an external denylist per check.
- **Key compromise:** an agent (or its operator) that suspects
  compromise MUST rotate immediately (§11.5) and SHOULD widely
  redistribute a `revocation` attestation for the pre-compromise state;
  every verifier's own choice of which issuers it trusts for
  `revocation` (§7) determines how quickly that actually stops trust
  elsewhere.
- **This format assumes each agent controls exactly one root key per
  `agent_id` at a time**, with delegate cards (§8) covering the
  legitimate need for multiple concurrently-active keys (parent + short-
  lived delegates). Sharing one `agent_id`'s root private key across
  multiple physically distinct running processes is out of scope and not
  recommended — mint each process its own genesis epoch instead.

## 13. Reference implementation

A Python reference implementation of §§2–4, 7–10 (the base chain,
renewal, attestation, delegate, bundle, and verification — Tier 1 only
at present) lives in `agent_id_card/` in this repository, with a CLI
(`aic`) demonstrating a full lifecycle. It is provided for convenience
and as a worked example; per §0, this document is the actual
specification, and the tiered disclosure model in §5 is normative
regardless of the reference code's current coverage of it.

## Appendix A: reproducible worked test vector

Every object below is REAL: genuine Ed25519 signatures over genuine RFC 8785 canonical bytes, genuine SHA-256 digests, built from four fixed, published, **test-only** private keys. Ed25519 signing is deterministic (RFC 8032) — any conformant implementation given the same private key and the same unsigned content MUST produce the exact same `signature.value` byte-for-byte. Use this to check a new implementation directly against this specification, not only against this repository's Python code.

**These four private keys are published in plaintext specifically so anyone can reproduce every signature below. They MUST NEVER be used for anything except testing a AIC implementation.**

| Role | Raw private key (32 bytes, all-same-byte for memorability) | private_b64 (base64url, unpadded) | agent_id |
|---|---|---|---|
| `alice` (subject, genesis + capability_update key) | `0x01` × 32 | `AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE` | `aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4` |
| `alice2` (subject, post-rotation key) | `0x04` × 32 | `BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ` | (same `agent_id` — key rotation preserves it) |
| `auditor` (independent attestation issuer) | `0x02` × 32 | `AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI` | `aic:agent:ajgD1fBZkCocba-8m6RykhL3yqwIY0zDrnaydSnwOCc` |
| `delegate_key` (ephemeral sub-identity) | `0x03` × 32 | `AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM` | n/a (delegate keys have no independent agent_id) |

Scenario: `alice` is genesis-issued (§3.1) with Tier 2 (§5.2) and Tier 3 (§5.3) content; gains a capability via a `capability_update` epoch (§3.2); then rotates to `alice2` via a `key_rotation` epoch (§3.3, carrying a `predecessor_signature` from `alice`'s key); is renewed (§4); is attested to by `auditor` (§7); and mints a delegate card (§8) for `delegate_key`. The final bundle (§9) discloses Tiers 1 and 2.

### A.1 Genesis epoch (epoch 0)

```json
{
  "aic": "1.0",
  "type": "epoch",
  "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
  "epoch_number": 0,
  "transition": "genesis",
  "prior_epoch_digest": null,
  "public_key": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
  "display_name": "warehouse-picker-07",
  "purpose": "Picks and packs warehouse orders in aisles 3-9; reports pick status to the WMS.",
  "capability_categories": [
    "actuate",
    "observe"
  ],
  "detailed_digest": "sha256:bf0024ae7b4439bd69a4b13850d3612148c273bbc18472e10497d7e611beb25e",
  "sensitive_digest": "sha256:e9d1aa52ce158eb566b7b50b8b586236413d9774cf7193dd93110bd25a14b225",
  "issued_at": "2026-08-31T12:00:00.000Z",
  "signature": {
    "alg": "Ed25519",
    "value": "I574uIICq46TQDT5IL6uiyvCkD1D8nTDGRl6W3sj2_FtZ-ovQeahsgEdWhHjiWf4wyod8rqFQJsvV1-VR5-OBw"
  }
}
```


### A.2 Tier 2 detail for epoch 0

Digest: `sha256:bf0024ae7b4439bd69a4b13850d3612148c273bbc18472e10497d7e611beb25e` — matches `genesis.detailed_digest` above.

```json
{
  "aic": "1.0",
  "type": "tier2_detail",
  "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
  "epoch_number": 0,
  "declared_capabilities": [
    "actuate.motors.forklift.v2",
    "observe.inventory.scan.v1"
  ],
  "operator": {
    "organization": "Acme Logistics",
    "contact": "fleet-ops@acme.example",
    "jurisdiction": "US-CA"
  },
  "protocols": [
    "fasp/1.0"
  ],
  "issued_at": "2026-08-31T12:00:00.000Z",
  "signature": {
    "alg": "Ed25519",
    "value": "iQel6P4d8VOowJg0GHNzVjC6HEtoBQo46Jpon4d024jfwxfXRSh_K4xT56QF6fMBFjk6wBLihUrTFHPg38uiDQ"
  }
}
```


### A.3 Tier 3 sensitive content for epoch 0

Digest: `sha256:e9d1aa52ce158eb566b7b50b8b586236413d9774cf7193dd93110bd25a14b225` — matches `genesis.sensitive_digest` above.

```json
{
  "aic": "1.0",
  "type": "tier3_sensitive",
  "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
  "epoch_number": 0,
  "model_name": "acme-picker-policy",
  "model_version": "4.2.1",
  "weights_digest": "sha256:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
  "base_model": "acme-picker-policy-3.9.0",
  "hardware": {
    "accelerator": "NVIDIA Jetson Orin NX",
    "accelerator_driver_version": "540.4.0",
    "firmware_version": "R36.3",
    "cpu": "ARM Cortex-A78AE",
    "os": "Linux",
    "os_version": "5.15.148-tegra"
  },
  "software_stack": {
    "runtime": "cpython",
    "runtime_version": "3.11.9",
    "library_versions": {
      "torch": "2.3.1",
      "onnxruntime-gpu": "1.18.0"
    }
  },
  "build_reference": "git:8f4c2ab@ci-run-40213",
  "issued_at": "2026-08-31T12:00:00.000Z",
  "signature": {
    "alg": "Ed25519",
    "value": "-EfAIDHuJfXyTyI0_lsIM3uLhzWcgWPEED6pk_jI_TPfP0P4zwtuoGgigCRoTz6TjYeaTQYOHPGueqDbVMrQAA"
  }
}
```


### A.4 Successor epoch 1 (`capability_update`)

`prior_epoch_digest` (`sha256:1a5916a2207bb96fb8ed09bb82d72856e367ee69442f9dbb6e2b00892f60bd55`) equals the genesis epoch's own digest, `sha256:1a5916a2207bb96fb8ed09bb82d72856e367ee69442f9dbb6e2b00892f60bd55`.

```json
{
  "aic": "1.0",
  "type": "epoch",
  "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
  "epoch_number": 1,
  "transition": "capability_update",
  "prior_epoch_digest": "sha256:1a5916a2207bb96fb8ed09bb82d72856e367ee69442f9dbb6e2b00892f60bd55",
  "public_key": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
  "display_name": "warehouse-picker-07",
  "purpose": "Picks and packs warehouse orders in aisles 3-9; reports pick status to the WMS.",
  "capability_categories": [
    "actuate",
    "coordinate",
    "observe"
  ],
  "detailed_digest": "sha256:fe639eb69b64908d52b6904d50c3ea97901c8d98d94a838444d3e7bc88c8dc7b",
  "sensitive_digest": "sha256:cd388325b5cdff78da1efbbf36641d8753dd00d27622e24338db1ec13ee66fae",
  "issued_at": "2026-09-14T08:30:00.000Z",
  "signature": {
    "alg": "Ed25519",
    "value": "0pXVN9c-8yRTzO6SgIRUxnMr1BOi_3QMiZgGHWLUmIMfVJK-rfM6TTIpvRSI62Mt4tL87b57n2w01_vUpu4eCQ"
  }
}
```


### A.5 Successor epoch 2 (`key_rotation`, alice → alice2)

`prior_epoch_digest` equals epoch 1's digest, `sha256:cd19c0ba77a27cf3f5868cecf679866a84eaf874bc607ce284814611b2d5ad45`. `signature` is by `alice2`'s new key; `predecessor_signature` is by `alice`'s OLD key over the identical unsigned content — verify it against epoch 1's `public_key`, not epoch 2's.

```json
{
  "aic": "1.0",
  "type": "epoch",
  "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
  "epoch_number": 2,
  "transition": "key_rotation",
  "prior_epoch_digest": "sha256:cd19c0ba77a27cf3f5868cecf679866a84eaf874bc607ce284814611b2d5ad45",
  "public_key": "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw",
  "display_name": "warehouse-picker-07",
  "purpose": "Picks and packs warehouse orders in aisles 3-9; reports pick status to the WMS.",
  "capability_categories": [
    "actuate",
    "coordinate",
    "observe"
  ],
  "detailed_digest": "sha256:f2fb2c6e662338b326a94b58c28d400b9c24910a1a19640f9e8f874f55462509",
  "sensitive_digest": "sha256:eca8046341c3bced59f738f992a947d8c82d5924332c9f531a92f5b53dd6a797",
  "issued_at": "2026-10-01T00:00:00.000Z",
  "signature": {
    "alg": "Ed25519",
    "value": "hDhGYJRbCgwtOVBCpdbeGJ9SGazR37EY9keyTJKbn4lDs-TyTTy_v1PZG_JonX6Xn-w278PRjhpcwqa7EWeUCw"
  },
  "predecessor_signature": {
    "alg": "Ed25519",
    "value": "9NL9lvr8krJF_lE84IQ_nlOb6S2VY3Vi2KbV1ttenwQAEkSCKqdi1mVbDq9kdK-KH90kXQAkh90OVxW8AaJpDA"
  }
}
```


### A.6 Tier 2 detail for epoch 2

Digest: `sha256:f2fb2c6e662338b326a94b58c28d400b9c24910a1a19640f9e8f874f55462509` — matches epoch 2's `detailed_digest` above. Signed by `alice2` (the now-active key).

```json
{
  "aic": "1.0",
  "type": "tier2_detail",
  "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
  "epoch_number": 2,
  "declared_capabilities": [
    "actuate.motors.forklift.v2",
    "observe.inventory.scan.v1",
    "coordinate.fleet.status.v1"
  ],
  "operator": {
    "organization": "Acme Logistics",
    "contact": "fleet-ops@acme.example",
    "jurisdiction": "US-CA"
  },
  "protocols": [
    "fasp/1.0"
  ],
  "issued_at": "2026-09-14T08:30:00.000Z",
  "signature": {
    "alg": "Ed25519",
    "value": "CiaVVQfU9UR6WfeH8uJiYxH1Bks56LuUhv0sFPRYiJEccd2AcwSzsTPYyOpGz85-W0LpRRoO3sSdPxmzIRviAQ"
  }
}
```


### A.7 Renewal of epoch 2

`epoch_digest` equals epoch 2's own digest, `sha256:f13607e49070fdb0b684d3f7a4fdbf213935c563c669316885746c783495dd28`.

```json
{
  "aic": "1.0",
  "type": "renewal",
  "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
  "epoch_digest": "sha256:f13607e49070fdb0b684d3f7a4fdbf213935c563c669316885746c783495dd28",
  "renewed_at": "2026-08-31T06:13:12.303Z",
  "valid_until": "2026-09-01T06:13:12.303Z",
  "signature": {
    "alg": "Ed25519",
    "value": "mRXeYL-g6bKBr311-FrRqojYb1h70fuRgTMXN-K-e5K4BLQoQmBhZq_1ZgvbtBrleSm6Lqgt1QIdHVw1Q7AKDA"
  }
}
```


### A.8 Attestation (`operator`, issued by `auditor`)

```json
{
  "aic": "1.0",
  "type": "attestation",
  "subject_agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
  "subject_epoch_digest": null,
  "kind": "operator",
  "issuer_id": "aic:agent:ajgD1fBZkCocba-8m6RykhL3yqwIY0zDrnaydSnwOCc",
  "issuer_public_key": "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q",
  "claim": {
    "organization": "Acme Logistics",
    "confirmed_via": "notarized operator agreement #4471"
  },
  "issued_at": "2026-08-31T12:05:00.000Z",
  "expires_at": null,
  "signature": {
    "alg": "Ed25519",
    "value": "MMncE6czPMzZD7eZZ3GkiJZ1_XDvIJpcAfstH0-eSjaR2hNP0s2qgl6cQu0rJR2ydVR97RjcTg1FmyHR1LFiDg"
  }
}
```


### A.9 Delegate card (parent: epoch 2, delegate: `delegate_key`)

`parent_epoch_digest` equals epoch 2's own digest, `sha256:f13607e49070fdb0b684d3f7a4fdbf213935c563c669316885746c783495dd28`. `scope_capability_prefixes` (`observe.inventory.`) narrows `declared_capabilities` in A.6 (`observe.inventory.scan.v1` starts with it).

```json
{
  "aic": "1.0",
  "type": "delegate",
  "parent_agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
  "parent_epoch_digest": "sha256:f13607e49070fdb0b684d3f7a4fdbf213935c563c669316885746c783495dd28",
  "delegate_public_key": "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E",
  "scope_capability_prefixes": [
    "observe.inventory."
  ],
  "purpose": "one aisle-7 cycle count",
  "max_actions": 50,
  "issued_at": "2026-08-31T13:00:00.000Z",
  "valid_until": "2026-08-31T13:30:00.000Z",
  "signature": {
    "alg": "Ed25519",
    "value": "gaxwoxi4i2JCJniyEWcl4V6jg9oyMb3w48rnep9mhCasDysdjq9gw1OSchYmlhul1Psxdd0KgLnGCaeF2SVmDg"
  }
}
```


### A.10 Full bundle, disclosing Tiers 1 and 2

```json
{
  "aic": "1.0",
  "type": "bundle",
  "disclosed_tiers": [
    1,
    2
  ],
  "epoch_chain": [
    {
      "aic": "1.0",
      "type": "epoch",
      "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
      "epoch_number": 0,
      "transition": "genesis",
      "prior_epoch_digest": null,
      "public_key": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
      "display_name": "warehouse-picker-07",
      "purpose": "Picks and packs warehouse orders in aisles 3-9; reports pick status to the WMS.",
      "capability_categories": [
        "actuate",
        "observe"
      ],
      "detailed_digest": "sha256:bf0024ae7b4439bd69a4b13850d3612148c273bbc18472e10497d7e611beb25e",
      "sensitive_digest": "sha256:e9d1aa52ce158eb566b7b50b8b586236413d9774cf7193dd93110bd25a14b225",
      "issued_at": "2026-08-31T12:00:00.000Z",
      "signature": {
        "alg": "Ed25519",
        "value": "I574uIICq46TQDT5IL6uiyvCkD1D8nTDGRl6W3sj2_FtZ-ovQeahsgEdWhHjiWf4wyod8rqFQJsvV1-VR5-OBw"
      }
    },
    {
      "aic": "1.0",
      "type": "epoch",
      "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
      "epoch_number": 1,
      "transition": "capability_update",
      "prior_epoch_digest": "sha256:1a5916a2207bb96fb8ed09bb82d72856e367ee69442f9dbb6e2b00892f60bd55",
      "public_key": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
      "display_name": "warehouse-picker-07",
      "purpose": "Picks and packs warehouse orders in aisles 3-9; reports pick status to the WMS.",
      "capability_categories": [
        "actuate",
        "coordinate",
        "observe"
      ],
      "detailed_digest": "sha256:fe639eb69b64908d52b6904d50c3ea97901c8d98d94a838444d3e7bc88c8dc7b",
      "sensitive_digest": "sha256:cd388325b5cdff78da1efbbf36641d8753dd00d27622e24338db1ec13ee66fae",
      "issued_at": "2026-09-14T08:30:00.000Z",
      "signature": {
        "alg": "Ed25519",
        "value": "0pXVN9c-8yRTzO6SgIRUxnMr1BOi_3QMiZgGHWLUmIMfVJK-rfM6TTIpvRSI62Mt4tL87b57n2w01_vUpu4eCQ"
      }
    },
    {
      "aic": "1.0",
      "type": "epoch",
      "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
      "epoch_number": 2,
      "transition": "key_rotation",
      "prior_epoch_digest": "sha256:cd19c0ba77a27cf3f5868cecf679866a84eaf874bc607ce284814611b2d5ad45",
      "public_key": "ypOsFwUYcHHWe4PH_w7-gQjo7EUwV113JoeTM9vavnw",
      "display_name": "warehouse-picker-07",
      "purpose": "Picks and packs warehouse orders in aisles 3-9; reports pick status to the WMS.",
      "capability_categories": [
        "actuate",
        "coordinate",
        "observe"
      ],
      "detailed_digest": "sha256:f2fb2c6e662338b326a94b58c28d400b9c24910a1a19640f9e8f874f55462509",
      "sensitive_digest": "sha256:eca8046341c3bced59f738f992a947d8c82d5924332c9f531a92f5b53dd6a797",
      "issued_at": "2026-10-01T00:00:00.000Z",
      "signature": {
        "alg": "Ed25519",
        "value": "hDhGYJRbCgwtOVBCpdbeGJ9SGazR37EY9keyTJKbn4lDs-TyTTy_v1PZG_JonX6Xn-w278PRjhpcwqa7EWeUCw"
      },
      "predecessor_signature": {
        "alg": "Ed25519",
        "value": "9NL9lvr8krJF_lE84IQ_nlOb6S2VY3Vi2KbV1ttenwQAEkSCKqdi1mVbDq9kdK-KH90kXQAkh90OVxW8AaJpDA"
      }
    }
  ],
  "detail": {
    "aic": "1.0",
    "type": "tier2_detail",
    "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
    "epoch_number": 2,
    "declared_capabilities": [
      "actuate.motors.forklift.v2",
      "observe.inventory.scan.v1",
      "coordinate.fleet.status.v1"
    ],
    "operator": {
      "organization": "Acme Logistics",
      "contact": "fleet-ops@acme.example",
      "jurisdiction": "US-CA"
    },
    "protocols": [
      "fasp/1.0"
    ],
    "issued_at": "2026-09-14T08:30:00.000Z",
    "signature": {
      "alg": "Ed25519",
      "value": "CiaVVQfU9UR6WfeH8uJiYxH1Bks56LuUhv0sFPRYiJEccd2AcwSzsTPYyOpGz85-W0LpRRoO3sSdPxmzIRviAQ"
    }
  },
  "sensitive": null,
  "renewal": {
    "aic": "1.0",
    "type": "renewal",
    "agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
    "epoch_digest": "sha256:f13607e49070fdb0b684d3f7a4fdbf213935c563c669316885746c783495dd28",
    "renewed_at": "2026-08-31T06:13:12.303Z",
    "valid_until": "2026-09-01T06:13:12.303Z",
    "signature": {
      "alg": "Ed25519",
      "value": "mRXeYL-g6bKBr311-FrRqojYb1h70fuRgTMXN-K-e5K4BLQoQmBhZq_1ZgvbtBrleSm6Lqgt1QIdHVw1Q7AKDA"
    }
  },
  "attestations": [
    {
      "aic": "1.0",
      "type": "attestation",
      "subject_agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
      "subject_epoch_digest": null,
      "kind": "operator",
      "issuer_id": "aic:agent:ajgD1fBZkCocba-8m6RykhL3yqwIY0zDrnaydSnwOCc",
      "issuer_public_key": "gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q",
      "claim": {
        "organization": "Acme Logistics",
        "confirmed_via": "notarized operator agreement #4471"
      },
      "issued_at": "2026-08-31T12:05:00.000Z",
      "expires_at": null,
      "signature": {
        "alg": "Ed25519",
        "value": "MMncE6czPMzZD7eZZ3GkiJZ1_XDvIJpcAfstH0-eSjaR2hNP0s2qgl6cQu0rJR2ydVR97RjcTg1FmyHR1LFiDg"
      }
    }
  ],
  "delegate": {
    "aic": "1.0",
    "type": "delegate",
    "parent_agent_id": "aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4",
    "parent_epoch_digest": "sha256:f13607e49070fdb0b684d3f7a4fdbf213935c563c669316885746c783495dd28",
    "delegate_public_key": "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E",
    "scope_capability_prefixes": [
      "observe.inventory."
    ],
    "purpose": "one aisle-7 cycle count",
    "max_actions": 50,
    "issued_at": "2026-08-31T13:00:00.000Z",
    "valid_until": "2026-08-31T13:30:00.000Z",
    "signature": {
      "alg": "Ed25519",
      "value": "gaxwoxi4i2JCJniyEWcl4V6jg9oyMb3w48rnep9mhCasDysdjq9gw1OSchYmlhul1Psxdd0KgLnGCaeF2SVmDg"
    }
  }
}
```

