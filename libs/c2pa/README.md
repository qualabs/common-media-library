# @svta/cml-c2pa

C2PA (Coalition for Content Provenance and Authenticity) live video validation for BMFF/MP4 containers.

## Installation

```bash
npm i @svta/cml-c2pa @svta/cml-iso-bmff cbor-x
```

> **Note:** `@svta/cml-iso-bmff` and `cbor-x` are peer dependencies.

## Quick start

### Validate an init segment

```typescript
import { validateC2paInitSegment } from '@svta/cml-c2pa'

const result = await validateC2paInitSegment(initSegmentBytes)
// result.isValid      — all checks passed
// result.errorCodes   — [] if valid, or C2PA failure codes (e.g. 'livevideo.init.invalid')
// result.sessionKeys  — validated session keys (kid, JWK, validity period)
// result.activeManifest — parsed C2PA manifest with assertions
```

### Validate a media segment (VSI/EMSG method)

```typescript
import { validateC2paSegment } from '@svta/cml-c2pa'

const validated = await validateC2paSegment(segmentBytes, sessionKeys)
if (!validated) {
  // No C2PA EMSG box found in segment
  return
}

const { result, nextSequenceState } = validated
// result.isValid        — all crypto checks passed
// result.errorCodes     — C2PA failure codes (e.g. 'livevideo.segment.invalid')
// result.sequenceNumber — segment sequence number from VSI
// result.sequenceResult — { reason: 'valid' | 'duplicate' | 'gap_detected' | ... }
// result.bmffHashHex    — computed BMFF hash
// result.kidHex         — session key ID used

// Pass nextSequenceState to the next call for sequence tracking:
const next = await validateC2paSegment(nextBytes, sessionKeys, nextSequenceState)
```

### Validate a manifest-box segment

```typescript
import { validateC2paManifestBoxSegment } from '@svta/cml-c2pa'

let lastManifestId = null
const { result, nextManifestId, nextState } = validateC2paManifestBoxSegment(
  segmentBytes, lastManifestId,
)
lastManifestId = nextManifestId
// result.isValid    — manifest parsed + all §19.7.2 checks passed
// result.errorCodes — C2PA failure codes (e.g. 'livevideo.continuityMethod.invalid')
```

## Public API

| Function | Description |
|---|---|
| `validateC2paInitSegment(bytes)` | Validate init segment: manifest, certificate, BMFF hash, session keys |
| `validateC2paSegment(bytes, sessionKeys, state?)` | Validate media segment via VSI/EMSG (returns `null` if no EMSG box) |
| `validateC2paManifestBoxSegment(bytes, lastId, state?)` | Validate manifest-box segment: parse, chain, assertions |
| `LiveVideoStatusCode` | C2PA §19.7 error code constants |

## Error codes

All validation results include an `errorCodes` array with standardized C2PA failure codes (§19.7):

| Code | Meaning |
|---|---|
| `livevideo.init.invalid` | Init segment contains an `mdat` box |
| `livevideo.manifest.invalid` | C2PA Manifest Box failed validation |
| `livevideo.segment.invalid` | Crypto failure: signature, hash, or key |
| `livevideo.assertion.invalid` | sequenceNumber or streamId mismatch |
| `livevideo.continuityMethod.invalid` | Continuity chain broken |
| `livevideo.sessionkey.invalid` | Session key invalid or expired |

## References

- [C2PA Specification v2.3](https://c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html)
- [JUMBF — ISO 19566-5](https://www.iso.org/standard/84635.html)
- [COSE — RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)
