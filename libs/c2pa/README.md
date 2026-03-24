# @svta/cml-c2pa

C2PA (Coalition for Content Provenance and Authenticity) manifest parsing and live stream verification for BMFF/MP4 containers.

## Installation

```bash
npm i @svta/cml-c2pa @svta/cml-iso-bmff cbor-x
```

> **Note:** `@svta/cml-iso-bmff` and `cbor-x` are peer dependencies and must be installed alongside this package.

## Quick start

### Validate an init segment

Parse the C2PA manifest, extract the certificate, verify the BMFF hash, and validate all session keys in one call:

```typescript
import { validateC2paInitSegment } from '@svta/cml-c2pa'

const result = await validateC2paInitSegment(initSegmentBytes)
// result.activeManifest — parsed C2PA manifest with assertions
// result.sessionKeys    — validated session keys (kid, JWK, validity period)
// result.bmffHashValid  — whether the BMFF hard-binding hash matches
// result.certificate    — DER-encoded signer certificate
```

### Validate a media segment (VSI/EMSG method)

Decode the EMSG/VSI data, then validate signature, hash, sequence number, and key expiry:

```typescript
import {
  validateC2paSegment,
  extractVsiEmsgBox,
  decodeCoseSign1,
  decodeVsiMap,
  createSequenceState,
} from '@svta/cml-c2pa'

const emsg = extractVsiEmsgBox(segmentBytes)
const coseSign1 = decodeCoseSign1(emsg.messageData)
const vsi = decodeVsiMap(coseSign1.payload)

let state = createSequenceState()
const { result, nextSequenceState } = await validateC2paSegment(
  segmentBytes, coseSign1, vsi, sessionKey, state,
)
state = nextSequenceState
// result.vsiValid        — combined C2PA validity (signature + hash + sequence + key)
// result.signatureValid  — COSE_Sign1 signature check
// result.hashValid       — BMFF content hash check
// result.sequenceResult  — { reason: 'valid' | 'duplicate' | 'gap_detected' | ... }
```

### Validate a manifest-box segment

For segments that embed the full C2PA manifest (no EMSG/VSI):

```typescript
import { validateC2paManifestBoxSegment } from '@svta/cml-c2pa'

let lastManifestId = null
const { result, nextManifestId } = validateC2paManifestBoxSegment(
  segmentBytes, lastManifestId,
)
lastManifestId = nextManifestId
// result.isValid              — manifest parsed + livevideo assertion present + chain intact
// result.hasLiveVideoAssertion — c2pa.livevideo.segment assertion found
// result.chainValid           — previousManifestId matches last known
```

### Parse a manifest (low-level)

```typescript
import { readC2paManifest } from '@svta/cml-c2pa'

const store = readC2paManifest(mp4Bytes)
const { activeManifest } = store

console.log(activeManifest.label)
// => 'urn:c2pa:1d3f8a55-e7f5-4317-a2c2-0db26c713ef0'

console.log(activeManifest.assertions.map(a => a.label))
// => ['c2pa.actions.v2', 'c2pa.session-keys', 'c2pa.hash.bmff.v3']

console.log(activeManifest.signatureInfo)
// => { issuer: 'Acme Content CA', time: '2025-01-15T12:00:00Z' }
```

## Public API

### High-level validation

| Function | Description |
|---|---|
| `validateC2paInitSegment(bytes)` | Validate init segment: manifest, certificate, BMFF hash, session keys |
| `validateC2paSegment(bytes, cose, vsi, key, state)` | Validate media segment: signature, hash, sequence, key expiry |
| `validateC2paManifestBoxSegment(bytes, lastId)` | Validate manifest-box segment: parse, chain, assertions |

### Manifest parsing

| Function | Description |
|---|---|
| `readC2paManifest(bytes)` | Parse C2PA manifest store from BMFF bytes |
| `extractManifestCertificate(bytes)` | Extract DER certificate from COSE_Sign1 x5chain |

### Decoders

| Function | Description |
|---|---|
| `decodeCoseSign1(bytes)` | Decode COSE_Sign1 structure (RFC 9052) |
| `decodeVsiMap(bytes)` | Decode CBOR VSI map from COSE payload |
| `parseEmsgBox(payload)` | Parse a single EMSG box |
| `extractVsiEmsgBox(segmentBytes)` | Find and parse the C2PA VSI EMSG box from segment bytes |

### Sequence tracking

| Function | Description |
|---|---|
| `createSequenceState()` | Create initial empty state |
| `validateSequenceNumber(state, seq, min)` | Detect duplicates, gaps, out-of-order, below-minimum |

### BMFF hashing

| Function | Description |
|---|---|
| `computeBmffHash(bytes, options)` | Compute BMFF content hash with exclusions |
| `validateBmffHash(bytes, expected, options)` | Validate BMFF hash against expected value |

## References

- [C2PA Specification v2.1](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html)
- [C2PA Live Video Streaming v1.0](https://c2pa.org/specifications/specifications/1.0/streaming/C2PA_Streaming_Specification.html)
- [JUMBF — ISO 19566-5](https://www.iso.org/standard/84635.html)
- [COSE — RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)
- [CBOR — RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)
