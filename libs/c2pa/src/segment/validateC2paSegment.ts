import type { CoseSign1 } from '../cose/CoseSign1.ts'
import { verifyCoseSign1 } from '../cose/verifyCoseSign1.ts'
import { LiveVideoStatusCode } from '../LiveVideoStatusCode.ts'
import type { VsiMap } from '../vsi/VsiMap.ts'
import type { SequenceState } from '../vsi/SequenceState.ts'
import { validateSequenceNumber } from '../vsi/validateSequenceNumber.ts'
import { validateBmffHash } from '../bmff/validateBmffHash.ts'
import type { ValidatedSessionKey } from '../init/InitSegmentValidation.ts'
import { isKeyExpired } from '../utils.ts'
import type { SegmentValidationResult } from './SegmentValidation.ts'

const KEY_TYPE_OKP = 'OKP'

function resolveImportAlgorithm(jwk: { kty: string; crv: string }): AlgorithmIdentifier | EcKeyImportParams {
	return jwk.kty === KEY_TYPE_OKP ? { name: jwk.crv } : { name: 'ECDSA', namedCurve: jwk.crv }
}

/**
 * Validates a C2PA live stream segment against a known session key.
 *
 * Performs all cryptographic checks defined in the C2PA spec §19.7.3:
 * signature verification, BMFF content hash, sequence number floor, and
 * key validity period.
 *
 * This function is **pure** — it does not access any external state. The
 * caller is responsible for looking up the session key and persisting
 * `nextSequenceState` between calls.
 *
 * @param segmentBytes - Raw segment bytes (used for BMFF hash computation)
 * @param coseSign1 - Decoded COSE_Sign1 from the segment's EMSG box
 * @param vsi - Decoded VSI map from the COSE_Sign1 payload
 * @param sessionKey - Session key for the kid in `coseSign1`, or null if not found
 * @param sequenceState - Current sequence state for this stream
 * @returns Validation result and the updated sequence state to persist
 *
 * @example
 * {@includeCode ../../test/segment/validateC2paSegment.test.ts#example}
 *
 * @public
 */
export async function validateC2paSegment(
	segmentBytes: Uint8Array,
	coseSign1: CoseSign1,
	vsi: VsiMap,
	sessionKey: ValidatedSessionKey | null,
	sequenceState: SequenceState,
): Promise<{ readonly result: SegmentValidationResult; readonly nextSequenceState: SequenceState }> {
	const minSequenceNumber = sessionKey?.minSequenceNumber ?? 0

	const { result: sequenceResult, nextState: nextSequenceState } = validateSequenceNumber(
		sequenceState,
		vsi.sequenceNumber,
		minSequenceNumber,
	)

	if (!sessionKey) {
		return {
			result: {
				sequenceResult,
				isValid: false,
				errorCodes: [LiveVideoStatusCode.SEGMENT_INVALID],
			},
			nextSequenceState,
		}
	}

	const algorithm = resolveImportAlgorithm(sessionKey.jwk)
	const publicKey = await crypto.subtle.importKey(
		'jwk',
		sessionKey.jwk as JsonWebKey,
		algorithm,
		false,
		['verify'],
	)

	const [signatureValid, hashValid] = await Promise.all([
		verifyCoseSign1(coseSign1, coseSign1.payload, publicKey),
		validateBmffHash(segmentBytes, vsi.bmffHash.hash, {
			exclusions: vsi.bmffHash.exclusions,
			alg: vsi.bmffHash.alg,
		}),
	])

	const sequenceAboveMin = vsi.sequenceNumber >= sessionKey.minSequenceNumber
	const keyExpired = isKeyExpired(sessionKey.createdAt, sessionKey.validityPeriod)

	const codes = new Set<LiveVideoStatusCode>()
	if (!signatureValid || !hashValid || !sequenceAboveMin) codes.add(LiveVideoStatusCode.SEGMENT_INVALID)
	if (keyExpired) codes.add(LiveVideoStatusCode.SESSIONKEY_INVALID)
	const errorCodes = [...codes]

	return {
		result: { sequenceResult, isValid: errorCodes.length === 0, errorCodes },
		nextSequenceState,
	}
}
