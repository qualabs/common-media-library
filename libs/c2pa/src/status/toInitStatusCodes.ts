import { LiveVideoStatusCode } from '../LiveVideoStatusCode.ts'
import type { InitSegmentValidation } from '../init/InitSegmentValidation.ts'

/**
 * Maps an {@link InitSegmentValidation} to an array of C2PA live video
 * failure status codes per §19.7.1 and §19.7.3.
 *
 * Returns an empty array when the init segment is fully valid.
 *
 * Note: if {@link validateC2paInitSegment} throws because an `mdat` box is
 * present, that corresponds to `livevideo.init.invalid`. This function only
 * handles the successfully-returned result.
 *
 * @param result - The validation result from {@link validateC2paInitSegment}
 * @returns Deduplicated array of applicable failure codes
 *
 * @public
 */
export function toInitStatusCodes(
	result: InitSegmentValidation,
): readonly LiveVideoStatusCode[] {
	const codes = new Set<LiveVideoStatusCode>()

	if (!result.bmffHashValid) {
		codes.add(LiveVideoStatusCode.INIT_INVALID)
	}
	if (result.sessionKeys.length === 0) {
		codes.add(LiveVideoStatusCode.SESSIONKEY_INVALID)
	}

	return [...codes]
}
