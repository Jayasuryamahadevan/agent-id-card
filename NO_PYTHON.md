# AIC without Python

This document is for exactly one situation: you are bootstrapping an AIC
identity (HARNESS_BOOTSTRAP.md) or signing/verifying any other AIC object
(SPEC.md), and **Python is not available on this system at all** -- a
ROS 2 node built in pure C++ with no `rclpy`, a firmware image, a
container with nothing but a single static binary, an embedded
controller. SPEC.md's format was designed so this is always possible:
Ed25519 signatures over RFC 8785 canonical JSON bytes, nothing more
exotic than that, and every step below is proven to interoperate with
this repository's own Python reference verifier -- not just asserted.

## Decision tree

1. **Do you have `openssl` (version 3.0 or later)?** Almost certainly
   yes if this is a Linux system of any recency -- including most ROS 2
   deployments, which typically already depend on OpenSSL for DDS
   Security/SROS2 even when there is no Python interpreter anywhere in
   the image. Use §1 below. Check with `openssl version`.
2. **Do you have Node.js?** Its built-in `crypto` module has supported
   Ed25519 natively since Node 12, with no external dependency. Use §2
   below.
3. **Do you have a C/C++ toolchain and can link `libsodium`?** Common in
   robotics stacks (often already a transitive dependency). Use §3
   below.
4. **None of the above, or genuinely no way to produce a real
   signature?** Do not fabricate one. Persist your discovered facts as
   an epoch object with `"signature": null` and `"unsigned": true`,
   and sign it for real the moment any of the above becomes available.
   HARNESS_BOOTSTRAP.md ss3 says the same thing; it applies here too.

Whichever path you take, canonicalization (RFC 8785) is the part that
is easy to get subtly wrong, because most languages' default JSON
serializers do NOT sort keys or format numbers the way JCS requires.
§4 gives the exact, minimal rule set for AIC's own schemas (which never
use floating-point numbers or exotic Unicode), so you do not need a full
general-purpose JCS library to get this right for the objects this
format actually defines.

## 1. OpenSSL (recommended default)

Generate a keypair:

```bash
openssl genpkey -algorithm ed25519 -out private.pem
openssl pkey -in private.pem -pubout -outform DER -out public.der
tail -c 32 public.der > public_raw.bin   # the last 32 bytes of the DER SPKI structure are the raw Ed25519 public key
```

`public_key` (and the key half of `agent_id`) is `base64url(public_raw.bin)`,
no padding:

```bash
base64 -w0 public_raw.bin | tr '+/' '-_' | tr -d '='
```

To sign: build the exact canonical JSON bytes for your object (§4) with
`signature` omitted entirely, into a file, then:

```bash
openssl pkeyutl -sign -inkey private.pem -rawin -in canonical_bytes.json -out signature.bin
base64 -w0 signature.bin | tr '+/' '-_' | tr -d '='   # this is signature.value
```

`-rawin` is required -- Ed25519 does not pre-hash its input, unlike
almost every other signature scheme, so the ordinary `openssl dgst -sign`
path (which pre-hashes) produces the wrong thing entirely and will not
verify. This needs OpenSSL 3.0+; 1.1.1 added Ed25519 key generation but
not raw-mode `pkeyutl` signing.

To verify (e.g. to sanity-check your own output before trusting it):

```bash
openssl pkeyutl -verify -pubin -inkey public.pem -rawin -in canonical_bytes.json -sigfile signature.bin
```

**This exact procedure was tested against this repository's Python
reference verifier while writing this document**: a genesis epoch and
its Tier 2 detail, signed with nothing but the `openssl` commands above,
both passed `agent_id_card.epoch.verify_epoch()` and
`agent_id_card.tiers.verify_detail()` unmodified. There is no special
case in the verifier for "was this signed by openssl" -- it is ordinary
Ed25519, and it just works.

## 2. Node.js

Node's built-in `crypto` needs no package install:

```js
const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

const rawPublicKey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
const publicKeyB64 = rawPublicKey.toString('base64url'); // Node's Buffer supports base64url directly

function sign(canonicalBytes) {
  return crypto.sign(null, canonicalBytes, privateKey).toString('base64url'); // null digest: Ed25519 does not pre-hash
}
```

Also tested end to end against the Python verifier in the same way as
§1: a Node-signed payload verified correctly via
`cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey.verify()`.

For RFC 8785 canonicalization specifically (rather than the minimal
by-hand rules in §4), the `canonicalize` npm package implements the full
spec if you'd rather depend on it than hand-rolling §4's subset.

## 3. libsodium (C/C++, common in robotics)

`crypto_sign_ed25519_keypair(pk, sk)` generates a keypair (`pk` is
already the raw 32-byte public key -- no DER unwrapping needed).
`crypto_sign_ed25519_detached(sig, &sig_len, canonical_bytes, canonical_len, sk)`
produces the 64-byte raw signature directly, again with no pre-hashing
step to worry about (libsodium's Ed25519 API is detached-signature-first
and matches AIC's needs almost exactly as-is). Base64url-encode `pk` and
`sig` the same way as §1/§2.

## 4. Manual RFC 8785 canonicalization for AIC's own schemas

You do not need a full JCS implementation to canonicalize an epoch,
Tier 2/3 object, renewal, attestation, or delegate card correctly --
none of AIC's own schemas use floating-point numbers, non-ASCII text is
optional and rare, and nesting is shallow. Follow these rules exactly
and you will produce byte-identical output to the reference
canonicalizer for every object this format defines:

1. Serialize as JSON with **no insignificant whitespace at all**: no
   spaces after `:` or `,`, no newlines, no trailing newline.
2. **Sort every object's keys** at every nesting level, byte-wise
   ascending by their UTF-8 representation (plain ASCII alphabetical
   order for every key AIC actually uses).
3. Strings: standard JSON escaping (`\"`, `\\`, `\n`, `\t`, etc.); AIC's
   own field values never require anything beyond that.
4. Integers (`epoch_number`, `max_actions`, ...): plain decimal, no
   leading zeros, no `.0` suffix -- exactly what every language's
   default integer-to-string already produces.
5. `null` for an absent optional value (never omit a *required* key,
   and never substitute `""` or `0` for "not present").
6. Booleans: literal `true`/`false`.
7. Arrays: preserve the given order exactly (arrays are NOT sorted --
   only object keys are).

This is the exact rule set that produced every canonical-bytes example
in this file and in SPEC.md's Appendix A. If you ever need to
canonicalize a value AIC doesn't define a schema for, use a real RFC 8785
library for your language instead of extending these ad hoc rules --
floating-point formatting in particular has real edge cases these seven
rules don't cover.

### Worked example

A Tier 2 detail object (based on, but not byte-identical to, SPEC.md
Appendix A's -- this one also carries the optional `known_limitations`
field), canonicalized by hand per the rules above. Verified against this
repository's own canonicalizer to confirm it is byte-for-byte what
`rfc8785.dumps()` produces for the same object -- these seven rules are
not just a paraphrase of RFC 8785, they reproduce it exactly for every
field shape AIC actually uses:

```
{"agent_id":"aic:agent:NHUPmL1Z_PyUbaRaqr6TO-FUpLUJThxKv0KGZQXzyX4","aic":"1.0","declared_capabilities":["actuate.motors.forklift.v2","observe.inventory.scan.v1"],"epoch_number":0,"issued_at":"2026-08-31T12:00:00.000Z","known_limitations":[],"operator":{"contact":"fleet-ops@acme.example","jurisdiction":"US-CA","organization":"Acme Logistics"},"protocols":["fasp/1.0"],"type":"tier2_detail"}
```

Notice: top-level keys are alphabetical (`agent_id` before `aic` before
`declared_capabilities`...), the nested `operator` object's keys are
ALSO sorted alphabetically independently of the surrounding object, and
`declared_capabilities`/`protocols` keep their given array order.
