---
title: Signer Trust Validation
description: Check the signing certificate against trust anchors, an allowed list, and accepted EKUs
---

# Signer Trust Validation

`isValid` tells you that the content is intact and that the claim signature verifies. It does not tell you who signed the content. Any party with a certificate can produce a manifest that validates.

A trust policy answers the second question. When you pass a policy, every validation result gets an `isTrusted` field. `isTrusted` is `true` when the policy trusts the signing certificate.

If the policy does not trust the signer, the result is not valid, as section 15.7 of C2PA 2.4 requires. `errorCodes` then contains the failure code of the policy. [Reading `isTrusted`](#reading-istrusted) lists the codes. Without a policy, the library does not check the signer.

## Creating a Policy

Create the policy once, when the player starts. Reuse the same policy for every track and every segment. The library does not download files. Load each trust source yourself and pass its text.

```typescript
import { createTrustPolicy } from '@svta/cml-c2pa'

const response = await fetch('https://example.com/c2pa/anchors.pem')
const trustPolicy = await createTrustPolicy({ trustAnchors: await response.text() })
```

The policy accepts three sources. It needs `trustAnchors`, `allowedList`, or both.

| Option | Content | Effect |
|--------|---------|--------|
| `trustAnchors` | PEM certificates of certificate authorities | Trusts a signer whose certificate chain leads to one of these certificates |
| `allowedList` | PEM certificates, or base64 SHA-256 hashes of DER certificates, one per line | Trusts exactly these signing certificates |
| `trustConfig` | Extended Key Usage (EKU) OIDs, one per line | Adds EKUs to the [accepted EKUs](#accepted-ekus) of a signer on the `trustAnchors` path |

The files have the same format as the `trust_anchors`, `allowed_list`, and `trust_config` settings of c2pa-rs.

### Source Errors

In `allowedList` and `trustConfig`, a line that starts with `#` or `//` is a comment. Text after `#` is also a comment. Every other line must be a valid entry.

`createTrustPolicy` rejects with one error that lists every problem in the sources:

- A PEM certificate does not parse, or a PEM block is not complete.
- A line of `allowedList` or `trustConfig` is not a valid entry.
- `trustAnchors` or `allowedList` has no entries.

So a policy that a validation function receives has loaded every source.

A policy is immutable. To use changed files, create a new policy.

### Validation Time

The policy compares validity periods with the current time. Two options change this comparison:

| Option | Default | Effect |
|--------|---------|--------|
| `validationTime` | `() => new Date()` | Returns the time to compare with validity periods |
| `clockTolerance` | `0` | Milliseconds of clock difference to accept at each end of a validity period |

Use `clockTolerance` on devices with a clock that may be wrong, such as smart TVs. Live streams often use short-lived certificates. A client clock that is a few minutes slow can then reject a new certificate.

### Custom Policies

`TrustPolicy` has one function, `evaluate`. It receives the `x5chain` and returns `null` for a trusted signer or a failure code. To use another trust service, pass your own object:

```typescript
import { C2paStatusCode, validateC2paInitSegment, type TrustPolicy } from '@svta/cml-c2pa'

const trustPolicy: TrustPolicy = {
  evaluate: async chain => (chain.length > 0 ? null : C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED),
}

const init = await validateC2paInitSegment(initBytes, { trustPolicy })
```

The validation functions import only the `TrustPolicy` type. The X.509 code is in the bundle only when your code imports `createTrustPolicy`.

## Trust Rules

The library evaluates the certificate chain from the `x5chain` header of the claim signature. The first certificate is the signing certificate.

1. **Allowed list.** If the SHA-256 hash of the signing certificate is on the allowed list, the signer is trusted. The library does not check the EKUs or the chain of this certificate. The library checks the key, the signature algorithm, and the validity period. [Certificate profile](#certificate-profile) lists the key and algorithm rules.
2. **Trust anchors.** Otherwise, the chain must lead to a trust anchor. The library verifies the signature of every certificate in the chain with the public key of its issuer. The chain can have at most 10 certificates.
3. **Issuing certificates.** Every issuing certificate must be a certificate authority with the `keyCertSign` key usage. It must be X.509 version 3, without an issuer or subject unique ID. It must have a subject key identifier. It must have an authority key identifier, unless it is self-signed.
4. **Certificate profile.** On the trust anchor path, the signing certificate must meet the certificate profile of C2PA 2.4 section 14.5.1.1. The rules follow this list.
5. **EKU.** On the trust anchor path, the signing certificate must carry at least one accepted EKU.
6. **Path constraints.** No certificate on the path can have an unknown critical extension. Every issuing certificate must respect its `pathLenConstraint`.
7. **Validity period.** The trust anchor must be valid at the validation time. Otherwise, the result has `signingCredential.untrusted`. The signing certificate and the CA certificates between it and the anchor must also be valid. Otherwise, the result has `claimSignature.outsideValidity` (section 15.8.2).

### Certificate Profile

The certificate profile requires these properties of the signing certificate:

- The signature algorithm of the certificate is ECDSA, RSASSA-PKCS1-v1_5, or RSASSA-PSS with SHA-256, SHA-384, or SHA-512. Ed25519 and ML-DSA are also allowed. RSASSA-PSS parameters name the same hash in `hashAlgorithm` and `maskGenAlgorithm`.
- The certificate is X.509 version 3, without an issuer or subject unique ID.
- The certificate is not a certificate authority. Its key usage contains `digitalSignature` and does not contain `keyCertSign`.
- The certificate has an authority key identifier, unless it is self-signed.
- The key is an EC key on P-256, P-384, or P-521, an RSA key with a modulus of at least 2048 bits, an Ed25519 key, or an ML-DSA key. C2PA 2.5 section 13.5.1.1 applies this rule only to the signing certificate. CA certificates can have other keys.
- The certificate does not carry `anyExtendedKeyUsage`. If it carries `id-kp-timeStamping` or `id-kp-OCSPSigning`, that EKU is its only EKU.

The library verifies certificates signed with ECDSA, RSASSA-PKCS1-v1_5, RSASSA-PSS, and Ed25519. WebCrypto does not support ML-DSA, and some runtimes do not support Ed25519. If the runtime cannot verify a signature of the chain, the result has `algorithm.unsupported`. The policy does not store that result, so the next call tries again.

### Accepted EKUs

Without `trustConfig`, the policy accepts the EKUs that section 14.4.1 of C2PA 2.4 names:

| OID | Name |
|-----|------|
| `1.3.6.1.4.1.62558.2.1` | `c2pa-kp-claimSigning` |
| `1.3.6.1.5.5.7.3.4` | `id-kp-emailProtection` |
| `1.3.6.1.5.5.7.3.36` | `id-kp-documentSigning` |

A `trustConfig` adds EKUs to this list, as in c2pa-rs.

## Validating Streams

### Manifest Box

Every Manifest Box segment carries its own certificate. Pass the policy in the options of every call.

```typescript
import { createTrustPolicy, validateC2paManifestBoxSegment } from '@svta/cml-c2pa'
import type { ManifestBoxValidationState } from '@svta/cml-c2pa'

const trustPolicy = await createTrustPolicy({ trustAnchors: anchorsPem })

let lastManifestId: string | null = null
let state: ManifestBoxValidationState | undefined

for (const segmentUrl of segmentUrls) {
  const response = await fetch(segmentUrl)
  const bytes = new Uint8Array(await response.arrayBuffer())
  const { result, nextManifestId, nextState } = await validateC2paManifestBoxSegment(
    bytes,
    lastManifestId,
    state,
    { trustPolicy },
  )
  lastManifestId = nextManifestId
  state = nextState

  console.log(result.isValid, result.isTrusted)
}
```

The policy stores the result for each certificate chain. The library verifies the signatures of a chain once, not once per segment. The policy keeps the results of the 64 chains that it used last.

A segment from a signer that the policy does not trust returns the received `lastManifestId` and `state`. So a forged segment cannot break the sequence of the real signer.

### VSI/EMSG and VOD Merkle

VSI and Merkle media segments carry no certificate. The certificate is in the init segment. Pass the policy to `validateC2paInitSegment` only.

```typescript
import { createTrustPolicy, validateC2paInitSegment, validateC2paSegment } from '@svta/cml-c2pa'
import type { SequenceState } from '@svta/cml-c2pa'

const trustPolicy = await createTrustPolicy({ trustAnchors: anchorsPem })

const init = await validateC2paInitSegment(initBytes, { trustPolicy })

let sequenceState: SequenceState | undefined
for (const segmentBytes of mediaSegments) {
  const validated = await validateC2paSegment(segmentBytes, init.sessionKeys, sequenceState)
  if (!validated) continue
  sequenceState = validated.nextSequenceState

  console.log(validated.result.isValid, validated.result.isTrusted)
}
```

`validateC2paInitSegment` sets `isTrusted` on the result, on every entry of `sessionKeys`, and on every entry of `merkleMaps`. `validateC2paSegment` copies `isTrusted` from the session key that matches the segment. `validateC2paMerkleSegment` copies `isTrusted` from the merkle maps that match the segment. The segment functions take no trust parameter. If `isTrusted` is `false`, the segment result has `signingCredential.untrusted`. The init segment result has the exact failure code.

## Reading `isTrusted`

| Value | Meaning |
|-------|---------|
| `true` | The policy trusts the signer |
| `false` | The policy does not trust the signer, the claim signature does not verify, or the manifest has no certificate |
| absent | No policy was passed, or no session key or merkle map matched the segment |

With a policy, `isValid: true` means that the signer is trusted. The reverse is not true. A segment with tampered content from a trusted signer has `isValid: false` and `isTrusted: true`. A claim signature that does not verify always gives `isTrusted: false`. Any party can copy the certificate chain of a trusted signer, so a chain alone proves nothing. To show one verdict, combine the two fields:

```typescript
function verdict(result: { readonly isValid: boolean; readonly isTrusted?: boolean }): 'invalid' | 'valid' | 'trusted' {
  if (!result.isValid) return 'invalid'
  return result.isTrusted ? 'trusted' : 'valid'
}
```

These three states use the names of the `validation_state` values of c2pa-rs: `Invalid`, `Valid`, and `Trusted`. With a policy, a result is `invalid` or `trusted`. A `valid` result needs a call without a policy.

Section 15.7 rejects the claim when the chain of trust cannot be verified. A rejected claim does not receive `claimSignature.validated`, so the manifest is not Valid (section 14.3.5). c2pa-rs reads this rule in another way. See [Differences from c2pa-rs](#differences-from-c2pa-rs).

| Signer | Without a policy | With a policy |
|--------|------------------|---------------|
| Chains to a trust anchor | `valid` | `trusted` |
| Does not chain to a trust anchor | `valid` | `invalid`, `signingCredential.untrusted` |
| Breaks the certificate profile | `valid` | `invalid`, `signingCredential.invalid` |
| Is outside its validity period | `valid` | `invalid`, `claimSignature.outsideValidity` |
| Uses an algorithm that the runtime cannot verify | `valid` | `invalid`, `algorithm.unsupported` |

## Differences from c2pa-rs

| Topic | This library | c2pa-rs |
|-------|--------------|---------|
| Untrusted signer | `isValid` is `false` (section 15.7) | `validation_state` is `Valid`. `signingCredential.untrusted` is a tolerated failure. |
| Default EKUs | The three EKUs of C2PA 2.4 section 14.4.1 | Also accepts `id-kp-timeStamping`, `id-kp-OCSPSigning`, and a Microsoft C2PA signing EKU |
| Validity period | Checked against the validation time | Checked against the time stamp of the signature, when one is present |
| Expired signing certificate | `claimSignature.outsideValidity` (section 15.8.2) | `signingCredential.expired` |
| Allowed list | Checks the key, the signature algorithm, and the validity period | Also applies the rest of the certificate profile |
| CA certificates | Checks the version, the unique IDs, and the key identifiers | Checks the profile of the signing certificate only |
| Critical name constraints or policy extensions | The chain fails | Accepted without processing |
| C2PA Trust List | Not included. Pass it as `trustAnchors`. | Not included |
| Key usage of the signing certificate | Requires `digitalSignature` | Also accepts `nonRepudiation` or `keyCertSign` |

## Limitations

- The library does not include the C2PA Trust List. Section 14.4.1 of C2PA 2.4 requires it for `c2pa-kp-claimSigning`. Pass it in `trustAnchors`.
- The library does not check revocation (OCSP or CRL).
- The library does not read the time stamp of the signature. Section 15.7 requires that check before the chain of trust. The library checks the validity period against the current time instead.
- The library does not check the certificate of the time stamp authority.
- The library does not process name constraints or policy extensions. A critical extension of these types makes the chain fail.
- The policy keeps one list of trust anchors for every accepted EKU. Section 14.4.1 asks for a list of anchors for each EKU. c2pa-rs also keeps one list.
- Without a policy, the library does not check the validity period of the signing certificate. Section 15.8.2 asks for that check in every validation.
- For VSI and Merkle streams, `isTrusted` reflects the time of the call to `validateC2paInitSegment`. The segments copy that value. For Manifest Box streams, the library compares the validity period with the current time at every segment.
