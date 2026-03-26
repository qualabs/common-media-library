import { LiveVideoStatusCode } from '../LiveVideoStatusCode.ts'
import type { SegmentValidationResult } from '../segment/SegmentValidation.ts'

/**
 * Maps a {@link SegmentValidationResult} (VSI/EMSG method) to an array of
 * C2PA live video failure status codes per §19.7.3.
 *
 * Returns an empty array when the segment is fully valid.
 *
 * @param result - The validation result from {@link validateC2paSegment}
 * @returns Deduplicated array of applicable failure codes
 *
 * @public
 */
export function toSegmentStatusCodes(
	result: SegmentValidationResult,
): readonly LiveVideoStatusCode[] {
	const codes = new Set<LiveVideoStatusCode>()

	if (!result.keyFound) {
		codes.add(LiveVideoStatusCode.SEGMENT_INVALID)
	}
	if (!result.signatureValid) {
		codes.add(LiveVideoStatusCode.SEGMENT_INVALID)
	}
	if (!result.hashValid) {
		codes.add(LiveVideoStatusCode.SEGMENT_INVALID)
	}
	if (!result.sequenceAboveMin) {
		codes.add(LiveVideoStatusCode.SEGMENT_INVALID)
	}
	if (result.keyExpired) {
		codes.add(LiveVideoStatusCode.SESSIONKEY_INVALID)
	}

	return [...codes]
}
