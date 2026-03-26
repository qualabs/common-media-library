import type { C2paManifestStore } from '../C2paManifest.ts'

/**
 * The result of validating a single C2PA manifest-box live stream segment.
 *
 * Returned by {@link validateC2paManifestBoxSegment}.
 *
 * `isValid` represents combined validity: the manifest was parsed successfully,
 * the `c2pa.livevideo.segment` assertion is present, the manifest ID chain
 * is intact, streamId matches, sequenceNumber is increasing, and continuityMethod
 * is present (C2PA spec §19.7.2).
 *
 * @public
 */
export type ManifestBoxValidationResult = {
  /** Parsed manifest store, or null if parsing failed */
  readonly manifest: C2paManifestStore | null
  /** Issuer string from signatureInfo, or null */
  readonly issuer: string | null
  /** Sequence number from c2pa.livevideo.segment, or null if assertion is absent */
  readonly sequenceNumber: number | null
  /** previousManifestId from c2pa.livevideo.segment, or null */
  readonly previousManifestId: string | null
  /** streamId from c2pa.livevideo.segment, or null if absent */
  readonly streamId: string | null
  /** continuityMethod from c2pa.livevideo.segment, or null if absent */
  readonly continuityMethod: string | null
  /** Hex-encoded hash bytes from c2pa.hash.bmff.v3, or null if assertion is absent */
  readonly bmffHashHex: string | null
  /** Whether the manifest was parsed and a claim is present */
  readonly claimSignatureValid: boolean
  /** Whether the c2pa.livevideo.segment assertion was found */
  readonly hasLiveVideoAssertion: boolean
  /** Whether the previousManifestId chain is intact */
  readonly chainValid: boolean
  /** Whether the streamId matches the previous segment (true if no previous segment) */
  readonly streamIdValid: boolean
  /** Whether the continuityMethod field is present in the assertion */
  readonly continuityMethodPresent: boolean
  /** Whether the sequenceNumber is strictly greater than the previous segment (true if no previous) */
  readonly sequenceNumberValid: boolean
  /** Overall validity: all checks pass */
  readonly isValid: boolean
}

/**
 * State to carry between consecutive manifest-box segment validations.
 *
 * Pass the `nextState` returned by {@link validateC2paManifestBoxSegment}
 * into the next call to enable streamId, sequenceNumber, and continuity checks.
 *
 * @public
 */
export type ManifestBoxValidationState = {
  readonly lastStreamId?: string | null
  readonly lastSequenceNumber?: number | null
}
