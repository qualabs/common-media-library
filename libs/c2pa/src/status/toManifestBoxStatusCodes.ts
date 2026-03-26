import { LiveVideoStatusCode } from '../LiveVideoStatusCode.ts'
import type { ManifestBoxValidationResult } from '../manifestbox/ManifestBoxValidation.ts'

/**
 * Maps a {@link ManifestBoxValidationResult} to an array of C2PA live video
 * failure status codes per §19.7.1 and §19.7.2.
 *
 * Returns an empty array when the segment is fully valid.
 *
 * @param result - The validation result from {@link validateC2paManifestBoxSegment}
 * @returns Deduplicated array of applicable failure codes
 *
 * @public
 */
export function toManifestBoxStatusCodes(
	result: ManifestBoxValidationResult,
): readonly LiveVideoStatusCode[] {
	const codes = new Set<LiveVideoStatusCode>()

	if (!result.claimSignatureValid) {
		codes.add(LiveVideoStatusCode.MANIFEST_INVALID)
	}
	if (!result.hasLiveVideoAssertion) {
		codes.add(LiveVideoStatusCode.ASSERTION_INVALID)
	}
	if (!result.streamIdValid) {
		codes.add(LiveVideoStatusCode.ASSERTION_INVALID)
	}
	if (!result.sequenceNumberValid) {
		codes.add(LiveVideoStatusCode.ASSERTION_INVALID)
	}
	if (!result.continuityMethodPresent) {
		codes.add(LiveVideoStatusCode.CONTINUITY_METHOD_INVALID)
	}
	if (!result.chainValid) {
		codes.add(LiveVideoStatusCode.CONTINUITY_METHOD_INVALID)
	}

	return [...codes]
}
