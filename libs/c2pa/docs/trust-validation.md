---
title: Signer Trust Validation
description: Check the signing certificate against trust anchors, an allowed list, and accepted EKUs
---

# Signer Trust Validation

`isValid` tells you that the content is intact and that the claim signature verifies. It does not tell you who signed the content. Any party with a certificate can produce a manifest that validates.

A trust policy answers the second question. When you pass a policy, every validation result gets an `isTrusted` field. `isTrusted` is `true` when the policy trusts the signing certificate.

If the policy does not trust the signer, the result is not valid. `errorCodes` then contains `signingCredential.untrusted` or `signingCredential.invalid`, as section 15.7 of C2PA 2.4 requires. Without a policy, the library does not check the signer.

## Creating a Policy

Create the policy once, when the player starts. Reuse the same policy for every track and every segment.

```typescript
import { createTrustPolicy } from '@svta/cml-c2pa'

const trustPolicy = await createTrustPolicy({
  trustAnchors: 'https://example.com/c2pa/anchors.pem',
  allowedList: 'https://example.com/c2pa/allowed.txt',
})

if (trustPolicy.loadErrors.length > 0) {
  console.warn('Trust policy is not available:', trustPolicy.loadErrors)
}
```

The policy accepts three sources. All sources are optional.

| Option | Content | Effect |
|--------|---------|--------|
| `trustAnchors` | PEM certificates of certificate authorities | Trusts a signer whose certificate chain leads to one of these certificates |
| `allowedList` | PEM certificates, or base64 SHA-256 hashes of DER certificates, one per line | Trusts exactly these signing certificates |
| `trustConfig` | Extended Key Usage (EKU) OIDs, one per line | Sets the EKUs that a signer on the `trustAnchors` path must carry |

The files have the same format as the `trust_anchors`, `allowed_list`, and `trust_config` settings of c2pa-rs.

### Source Formats

Each option is one string. The library detects the kind of string:

1. If the string contains `-----BEGIN` or a line break, the library uses it as content.
2. If the string starts with `http://` or `https://`, the library downloads it with `fetch`.
3. Any other string is a local file path. Local paths require Node.

An inline `allowedList` with a single hash line has no line break. Add `\n` at the end of the string, or the library reads the string as a file path.

`fetch` runs once, without retries. If you need a custom transport, download the file yourself and pass the content.

### Load Errors

`createTrustPolicy` never rejects because of a trust source. A source fails when the library cannot load it, when a certificate in it does not parse, or when the source has no usable entries. Each failure adds one message to `loadErrors`. The message names the option, the source, and the reason.

If any source fails, the policy trusts no certificate. The library does not use the other sources of that policy. Every result that the policy evaluates is then not valid, with `signingCredential.untrusted`. Check `loadErrors` before you use the policy.

A policy is immutable. To use changed files, create a new policy.

## Trust Rules

The library evaluates the certificate chain from the `x5chain` header of the claim signature. The first certificate is the signing certificate.

1. **Allowed list.** If the SHA-256 hash of the signing certificate is on the allowed list, the signer is trusted. The library does not check the EKUs or the validity period of this certificate. The library checks only the key: an EC key uses P-256, P-384, or P-521, and an RSA key has at least 2048 bits.
2. **Trust anchors.** Otherwise, the chain must lead to a trust anchor. The library verifies the signature of every certificate in the chain with the public key of its issuer. Every issuing certificate must be a certificate authority with the `keyCertSign` key usage.
3. **Certificate profile.** On the trust anchor path, the signing certificate must meet the certificate profile of C2PA 2.4 section 14.5.1.1. The rules follow this list.
4. **EKU.** On the trust anchor path, the signing certificate must carry at least one accepted EKU.
5. **Path constraints.** No certificate on the path can have an unknown critical extension. Every issuing certificate must respect its `pathLenConstraint`.
6. **Validity period.** On the trust anchor path, every certificate must be valid at the current time.

The certificate profile requires these properties of the signing certificate:

- The certificate is X.509 version 3, without an issuer or subject unique ID.
- The certificate is not a certificate authority. Its key usage contains `digitalSignature` and does not contain `keyCertSign`.
- The certificate has an authority key identifier, unless it is self-signed.
- An EC key uses P-256, P-384, or P-521. An RSA key has a modulus of at least 2048 bits.
- The certificate does not carry `anyExtendedKeyUsage`. If it carries `id-kp-timeStamping` or `id-kp-OCSPSigning`, that EKU is its only EKU.

The library supports certificates signed with ECDSA, RSASSA-PKCS1-v1_5, RSASSA-PSS, and Ed25519.

### Accepted EKUs

Without `trustConfig`, the policy accepts the EKUs that section 14.4.1 of C2PA 2.4 names:

| OID | Name |
|-----|------|
| `1.3.6.1.4.1.62558.2.1` | `c2pa-kp-claimSigning` |
| `1.3.6.1.5.5.7.3.4` | `id-kp-emailProtection` |
| `1.3.6.1.5.5.7.3.36` | `id-kp-documentSigning` |

A `trustConfig` replaces this list. The library ignores blank lines, `#` comments, and every line that is not an OID.

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
  const bytes = new Uint8Array(await fetch(segmentUrl).then(r => r.arrayBuffer()))
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

The policy stores the result for each certificate chain. The library verifies the signatures of a chain once, not once per segment. The policy keeps the results of the last 64 chains that it verified.

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

`validateC2paInitSegment` sets `isTrusted` on the result, on every entry of `sessionKeys`, and on every entry of `merkleMaps`. `validateC2paSegment` copies `isTrusted` from the session key that matches the segment. `validateC2paMerkleSegment` copies `isTrusted` from the merkle maps that match the segment. The segment functions take no trust parameter.

## Reading `isTrusted`

| Value | Meaning |
|-------|---------|
| `true` | The policy trusts the signer |
| `false` | The policy does not trust the signer, the claim signature does not verify, the manifest has no certificate, or the policy has load errors |
| absent | No policy was passed, or no session key or merkle map matched the segment |

With a policy, `isValid: true` means that the signer is trusted. The reverse is not true. A segment with tampered content from a trusted signer has `isValid: false` and `isTrusted: true`. A claim signature that does not verify always gives `isTrusted: false`. Any party can copy the certificate chain of a trusted signer, so a chain alone proves nothing. To show one verdict, combine the two fields:

```typescript
function verdict(result: { readonly isValid: boolean; readonly isTrusted?: boolean }): 'invalid' | 'valid' | 'trusted' {
  if (!result.isValid) return 'invalid'
  return result.isTrusted ? 'trusted' : 'valid'
}
```

These three states match the `validation_state` values of c2pa-rs: `Invalid`, `Valid`, and `Trusted`. With a policy, a result is `invalid` or `trusted`. A `valid` result needs a call without a policy.

| Signer | Without a policy | With a policy |
|--------|------------------|---------------|
| Chains to a trust anchor | `valid` | `trusted` |
| Does not chain to a trust anchor | `valid` | `invalid`, `signingCredential.untrusted` |
| Breaks the certificate profile | `valid` | `invalid`, `signingCredential.invalid` |

## Differences from c2pa-rs

| Topic | This library | c2pa-rs |
|-------|--------------|---------|
| Default EKUs | The three EKUs of C2PA 2.4 section 14.4.1 | Also accepts `id-kp-timeStamping`, `id-kp-OCSPSigning`, and a Microsoft C2PA signing EKU |
| `trustConfig` | Replaces the default EKUs | Adds to the default EKUs |
| Validity period | Checked against the current time | Checked against the time stamp of the signature, when one is present |
| C2PA Trust List | Not included. Pass it as `trustAnchors`. | Not included |
| Key usage of the signing certificate | Requires `digitalSignature` | Also accepts `nonRepudiation` or `keyCertSign` |

## Limitations

- The library does not include the C2PA Trust List. Section 14.4.1 of C2PA 2.4 requires it for `c2pa-kp-claimSigning`. Pass it in `trustAnchors`.
- The library does not check revocation (OCSP or CRL).
- The library does not read the time stamp of the signature. Section 15.7 requires that check before the chain of trust. The library checks the validity period against the current time instead.
- The library does not check the certificate of the time stamp authority.
- The library does not apply name constraints or policy constraints. A critical extension of these types does not make a chain fail.
- For VSI and Merkle streams, `isTrusted` reflects the time of the call to `validateC2paInitSegment`. The segments copy that value. For Manifest Box streams, the library compares the validity period with the current time at every segment.
