import type { C2paManifestStore } from '../C2paManifest.ts'

/**
 * The result of validating a single C2PA manifest-box live stream segment.
 *
 * Returned by {@link validateC2paManifestBoxSegment}.
 *
 * `isValid` represents combined validity: the manifest was parsed successfully,
 * the `c2pa.livevideo.segment` assertion is present, and the manifest ID chain
 * is intact. BMFF hash verification is not performed here — the native parser
 * does not expose a separate signature check.
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
  /** Hex-encoded hash bytes from c2pa.hash.bmff.v3, or null if assertion is absent */
  readonly bmffHashHex: string | null
  /** Whether the manifest was parsed and a claim is present */
  readonly claimSignatureValid: boolean
  /** Whether the c2pa.livevideo.segment assertion was found */
  readonly hasLiveVideoAssertion: boolean
  /** Whether the previousManifestId chain is intact */
  readonly chainValid: boolean
  /** Overall validity: claimSignatureValid && hasLiveVideoAssertion && chainValid */
  readonly isValid: boolean
}
