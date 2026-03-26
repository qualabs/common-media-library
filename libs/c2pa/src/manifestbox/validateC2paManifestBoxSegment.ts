import { LiveVideoStatusCode } from '../LiveVideoStatusCode.ts'
import { readC2paManifest } from '../readC2paManifest.ts'
import { bytesToHex } from '../utils.ts'
import type { ManifestBoxValidationResult, ManifestBoxValidationState } from './ManifestBoxValidation.ts'

const LIVE_VIDEO_ASSERTION_LABEL = 'c2pa.livevideo.segment'
const BMFF_HASH_ASSERTION_LABEL = 'c2pa.hash.bmff.v3'
const MANIFEST_ID_PREFIX_PATTERN = /^(xmp:iid:|urn:uuid:)/i

function normalizeManifestId(id: string | null): string | null {
	if (!id) return null
	return id.replace(MANIFEST_ID_PREFIX_PATTERN, '').toLowerCase()
}

function extractAssertionData(data: unknown): Record<string, unknown> | null {
	if (data !== null && typeof data === 'object' && !Array.isArray(data)) {
		return data as Record<string, unknown>
	}
	return null
}

/**
 * Validates a C2PA manifest-box live stream segment.
 *
 * Parses the C2PA manifest embedded in the segment and validates per §19.7.1 and §19.7.2.
 *
 * This function is **pure** — it does not access any external state. The
 * caller is responsible for persisting `nextManifestId` and `nextState`
 * between calls.
 *
 * @param bytes - Raw segment bytes
 * @param lastManifestId - Manifest ID from the previous segment, or null for the first segment
 * @param state - Optional state from the previous segment for streamId/sequenceNumber checks
 * @returns Validation result, the manifest ID, and state to persist for the next call
 *
 * @example
 * {@includeCode ../../test/manifestbox/validateC2paManifestBoxSegment.test.ts#example}
 *
 * @public
 */
export function validateC2paManifestBoxSegment(
	bytes: Uint8Array,
	lastManifestId: string | null,
	state?: ManifestBoxValidationState,
): {
	readonly result: ManifestBoxValidationResult
	readonly nextManifestId: string | null
	readonly nextState: ManifestBoxValidationState
} {
	let manifest = null
	let issuer: string | null = null
	let sequenceNumber: number | null = null
	let previousManifestId: string | null = null
	let streamId: string | null = null
	let continuityMethod: string | null = null
	let bmffHashHex: string | null = null
	let claimSignatureValid = false
	let hasLiveVideoAssertion = false

	try {
		manifest = readC2paManifest(bytes)
		const activeManifest = manifest?.activeManifest

		if (activeManifest) {
			claimSignatureValid = true
			issuer = activeManifest.signatureInfo?.issuer ?? null

			const liveVideoAssertion = activeManifest.assertions?.find(
				a => a.label === LIVE_VIDEO_ASSERTION_LABEL,
			)
			if (liveVideoAssertion) {
				hasLiveVideoAssertion = true
				const liveVideoData = extractAssertionData(liveVideoAssertion.data)
				const rawSeq = liveVideoData?.['sequenceNumber']
				sequenceNumber = typeof rawSeq === 'number' ? rawSeq : null
				const rawPrev = liveVideoData?.['previousManifestId']
				previousManifestId = typeof rawPrev === 'string' ? rawPrev : null
				const rawStreamId = liveVideoData?.['streamId']
				streamId = typeof rawStreamId === 'string' ? rawStreamId : null
				const rawContinuity = liveVideoData?.['continuityMethod']
				continuityMethod = typeof rawContinuity === 'string' ? rawContinuity : null
			}

			const hashAssertion = activeManifest.assertions?.find(
				a => a.label === BMFF_HASH_ASSERTION_LABEL,
			)
			if (hashAssertion) {
				const hashData = extractAssertionData(hashAssertion.data)
				const rawHash = hashData?.['hash'] ?? hashData?.['value']
				if (rawHash instanceof Uint8Array) {
					bmffHashHex = bytesToHex(rawHash)
				} else if (Array.isArray(rawHash)) {
					bmffHashHex = bytesToHex(new Uint8Array(rawHash as number[]))
				}
			}
		}
	} catch {
		claimSignatureValid = false
	}

	const currentManifestId = manifest?.activeManifest?.instanceId ?? null

	let chainValid: boolean
	if (!lastManifestId) {
		chainValid = hasLiveVideoAssertion
	} else {
		chainValid =
			!!previousManifestId &&
			normalizeManifestId(previousManifestId) === normalizeManifestId(lastManifestId)
	}

	const streamIdValid =
		state?.lastStreamId == null || streamId === state.lastStreamId
	const continuityMethodPresent = continuityMethod !== null
	const sequenceNumberValid =
		state?.lastSequenceNumber == null ||
		(sequenceNumber !== null && sequenceNumber > state.lastSequenceNumber)

	const codes = new Set<LiveVideoStatusCode>()
	if (!claimSignatureValid) codes.add(LiveVideoStatusCode.MANIFEST_INVALID)
	if (!hasLiveVideoAssertion) codes.add(LiveVideoStatusCode.ASSERTION_INVALID)
	if (!streamIdValid) codes.add(LiveVideoStatusCode.ASSERTION_INVALID)
	if (!sequenceNumberValid) codes.add(LiveVideoStatusCode.ASSERTION_INVALID)
	if (!continuityMethodPresent) codes.add(LiveVideoStatusCode.CONTINUITY_METHOD_INVALID)
	if (!chainValid) codes.add(LiveVideoStatusCode.CONTINUITY_METHOD_INVALID)
	const errorCodes = [...codes]

	const nextState: ManifestBoxValidationState = {
		lastStreamId: streamId ?? state?.lastStreamId ?? null,
		lastSequenceNumber: sequenceNumber ?? state?.lastSequenceNumber ?? null,
	}

	return {
		result: {
			manifest,
			issuer,
			sequenceNumber,
			previousManifestId,
			streamId,
			continuityMethod,
			bmffHashHex,
			isValid: errorCodes.length === 0,
			errorCodes,
		},
		nextManifestId: currentManifestId ?? lastManifestId,
		nextState,
	}
}
