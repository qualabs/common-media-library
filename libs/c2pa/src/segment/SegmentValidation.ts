import type { SequenceValidationResult } from '../vsi/SequenceState.ts'

/**
 * The result of validating a single C2PA live stream segment.
 *
 * Returned by {@link validateC2paSegment}.
 *
 * `vsiValid` represents the combined C2PA cryptographic validity (signature,
 * hash, sequence floor, and key expiry). Sequence anomalies (duplicate,
 * out-of-order, gap) are reported separately in `sequenceResult` so callers
 * can distinguish between cryptographic failures and delivery anomalies.
 *
 * @public
 */
export type SegmentValidationResult = {
  /** Whether a session key was found for the segment's kid */
  readonly keyFound: boolean
  /** Whether the COSE_Sign1 signature is valid */
  readonly signatureValid: boolean
  /** Whether the BMFF content hash matches the assertion */
  readonly hashValid: boolean
  /** Whether the segment's sequence number is \>= the key's minSequenceNumber */
  readonly sequenceAboveMin: boolean
  /** Whether the session key's validity period has expired */
  readonly keyExpired: boolean
  /** Sequence number validation result (duplicate, gap, out-of-order, valid) */
  readonly sequenceResult: SequenceValidationResult
  /** Combined C2PA validity: all crypto checks pass */
  readonly vsiValid: boolean
}
