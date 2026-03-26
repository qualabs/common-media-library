/**
 * C2PA (Coalition for Content Provenance and Authenticity) manifest parsing
 * for BMFF/MP4 containers, including live streaming support (VSI/EMSG).
 *
 * @see {@link https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html | C2PA Specification}
 * @see {@link https://c2pa.org/specifications/specifications/1.0/streaming/C2PA_Streaming_Specification.html | C2PA Live Video Streaming}
 *
 * @packageDocumentation
 */

// Main functions
export * from './readC2paManifest.ts'
export * from './extractManifestCertificate.ts'
export * from './init/validateC2paInitSegment.ts'
export * from './segment/validateC2paSegment.ts'
export type * from './init/InitSegmentValidation.ts'
export type * from './segment/SegmentValidation.ts'

// Types
export type * from './C2paAssertion.ts'
export type * from './C2paManifest.ts'
export type * from './C2paSignatureInfo.ts'

// Sub-modules: COSE
export * from './cose/decodeCoseSign1.ts'
export type * from './cose/CoseSign1.ts'
export type * from './cose/CoseKeyJwk.ts'

// Sub-modules: EMSG
export * from './emsg/parseEmsgBox.ts'
export type * from './emsg/EmsgBox.ts'

// Sub-modules: VSI
export * from './vsi/decodeVsiMap.ts'
export * from './vsi/validateSequenceNumber.ts'
export type * from './vsi/VsiMap.ts'
export type * from './vsi/SequenceState.ts'

// Sub-modules: ManifestBox
export * from './manifestbox/validateC2paManifestBoxSegment.ts'
export type * from './manifestbox/ManifestBoxValidation.ts'

// Status codes (C2PA §19.7)
export * from './LiveVideoStatusCode.ts'
export * from './status/toSegmentStatusCodes.ts'
export * from './status/toManifestBoxStatusCodes.ts'
export * from './status/toInitStatusCodes.ts'

// Sub-modules: BMFF hashing
export * from './bmff/computeBmffHash.ts'
export * from './bmff/validateBmffHash.ts'
export type * from './bmff/BmffHashExclusion.ts'
