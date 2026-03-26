import type { LiveVideoStatusCode } from '../LiveVideoStatusCode.ts'
import type { SequenceValidationResult } from '../vsi/SequenceState.ts'

/**
 * The result of validating a single C2PA live stream segment.
 *
 * Returned by {@link validateC2paSegment}.
 *
 * @public
 */
export type SegmentValidationResult = {
  readonly sequenceResult: SequenceValidationResult
  readonly isValid: boolean
  readonly errorCodes: readonly LiveVideoStatusCode[]
}
