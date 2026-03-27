import type { C2paAssertion } from '../C2paAssertion.ts'
import type { C2paManifestStore } from '../C2paManifest.ts'
import { LiveVideoStatusCode } from '../LiveVideoStatusCode.ts'
import { readC2paManifest } from '../readC2paManifest.ts'
import { bytesToHex } from '../utils.ts'
import type { ManifestBoxValidationResult, ManifestBoxValidationState } from './ManifestBoxValidation.ts'
import { validateBmffHash } from '../bmff/validateBmffHash.ts'
import type { BmffHashConstraint, BmffHashExclusion } from '../bmff/BmffHashExclusion.ts'

const LIVE_VIDEO_ASSERTION_LABEL = 'c2pa.livevideo.segment'
const BMFF_HASH_ASSERTION_LABEL = 'c2pa.hash.bmff.v3'
const MANIFEST_ID_PREFIX_PATTERN = /^(xmp:iid:|urn:uuid:)/i
const CONTINUITY_METHOD_MANIFEST_ID = 'c2pa.manifestId'
const SUPPORTED_CONTINUITY_METHODS = new Set([CONTINUITY_METHOD_MANIFEST_ID])
const SHA_ALGORITHM_PATTERN = /^sha(\d+)$/i

function normalizeAlgorithmName(rawAlg: string): string {
	return rawAlg.replace(SHA_ALGORITHM_PATTERN, 'SHA-$1')
}

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

type LiveVideoFields = {
	sequenceNumber: number | null
	previousManifestId: string | null
	streamId: string | null
	continuityMethod: string | null
}

function parseLiveVideoAssertion(assertions: readonly C2paAssertion[]): LiveVideoFields | null {
	const assertion = assertions.find(a => a.label === LIVE_VIDEO_ASSERTION_LABEL)
	if (!assertion) return null

	const data = extractAssertionData(assertion.data)
	const rawSeq = data?.['sequenceNumber']
	const rawPrev = data?.['previousManifestId']
	const rawStreamId = data?.['streamId']
	const rawContinuity = data?.['continuityMethod']

	return {
		sequenceNumber: typeof rawSeq === 'number' ? rawSeq : null,
		previousManifestId: typeof rawPrev === 'string' ? rawPrev : null,
		streamId: typeof rawStreamId === 'string' ? rawStreamId : null,
		continuityMethod: typeof rawContinuity === 'string' ? rawContinuity : null,
	}
}

type BmffHashFields = {
	hashBytes: Uint8Array | null
	hashHex: string | null
	exclusions: readonly BmffHashExclusion[]
	alg: string | undefined
}

function parseBmffHashAssertion(assertions: readonly C2paAssertion[]): BmffHashFields {
	const assertion = assertions.find(a => a.label === BMFF_HASH_ASSERTION_LABEL)
	if (!assertion) return { hashBytes: null, hashHex: null, exclusions: [], alg: undefined }

	const data = extractAssertionData(assertion.data)
	if (!data) return { hashBytes: null, hashHex: null, exclusions: [], alg: undefined }

	const rawHash = data['hash'] ?? data['value']
	let hashBytes: Uint8Array | null = null
	if (rawHash instanceof Uint8Array) hashBytes = rawHash
	else if (Array.isArray(rawHash)) hashBytes = new Uint8Array(rawHash as number[])

	const hashHex = hashBytes ? bytesToHex(hashBytes) : null
	const alg = typeof data['alg'] === 'string' ? normalizeAlgorithmName(data['alg']) : undefined

	const exclusions: BmffHashExclusion[] = []
	const rawExclusions = data['exclusions']
	if (Array.isArray(rawExclusions)) {
		for (const exc of rawExclusions) {
			if (!exc || typeof exc !== 'object') continue
			const excRecord = exc as Record<string, unknown>
			if (typeof excRecord['xpath'] !== 'string') continue
			const xpath = excRecord['xpath']
			const rawConstraints = excRecord['data']
			if (!Array.isArray(rawConstraints) || rawConstraints.length === 0) {
				exclusions.push({ xpath })
				continue
			}
			const constraints: BmffHashConstraint[] = []
			for (const c of rawConstraints) {
				if (!c || typeof c !== 'object') continue
				const cRecord = c as Record<string, unknown>
				if (typeof cRecord['offset'] !== 'number') continue
				const rawValue = cRecord['value']
				if (rawValue instanceof Uint8Array) {
					constraints.push({ offset: cRecord['offset'], value: rawValue })
				} else if (Array.isArray(rawValue)) {
					constraints.push({ offset: cRecord['offset'], value: new Uint8Array(rawValue as number[]) })
				}
			}
			exclusions.push(constraints.length > 0 ? { xpath, data: constraints } : { xpath })
		}
	}

	return { hashBytes, hashHex, exclusions, alg }
}

function parseManifest(bytes: Uint8Array): {
	manifest: C2paManifestStore | null
	issuer: string | null
	liveVideo: LiveVideoFields | null
	bmff: BmffHashFields
} {
	const nullBmff: BmffHashFields = { hashBytes: null, hashHex: null, exclusions: [], alg: undefined }
	try {
		const manifest = readC2paManifest(bytes)
		const activeManifest = manifest?.activeManifest
		if (!activeManifest) return { manifest, issuer: null, liveVideo: null, bmff: nullBmff }

		return {
			manifest,
			issuer: activeManifest.signatureInfo?.issuer ?? null,
			liveVideo: parseLiveVideoAssertion(activeManifest.assertions),
			bmff: parseBmffHashAssertion(activeManifest.assertions),
		}
	} catch {
		return { manifest: null, issuer: null, liveVideo: null, bmff: nullBmff }
	}
}

/**
 * Validates a C2PA manifest-box live stream segment.
 *
 * Parses the C2PA manifest embedded in the segment and validates per §19.7.1 and §19.7.2.
 * Recomputes the `c2pa.hash.bmff.v3` content hash from the raw segment bytes and compares
 * it against the expected hash in the manifest assertion.
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
export async function validateC2paManifestBoxSegment(
	bytes: Uint8Array,
	lastManifestId: string | null,
	state?: ManifestBoxValidationState,
): Promise<{
	readonly result: ManifestBoxValidationResult
	readonly nextManifestId: string | null
	readonly nextState: ManifestBoxValidationState
}> {
	const { manifest, issuer, liveVideo, bmff } = parseManifest(bytes)
	const hasManifest = manifest !== null
	const hasLiveVideo = liveVideo !== null

	const sequenceNumber = liveVideo?.sequenceNumber ?? null
	const previousManifestId = liveVideo?.previousManifestId ?? null
	const streamId = liveVideo?.streamId ?? null
	const continuityMethod = liveVideo?.continuityMethod ?? null

	const streamIdValid = state?.lastStreamId == null || streamId === state.lastStreamId
	const sequenceNumberValid =
		state?.lastSequenceNumber == null ||
		(sequenceNumber !== null && sequenceNumber > state.lastSequenceNumber)

	let bmffHashValid: boolean | null = null
	if (bmff.hashBytes !== null) {
		bmffHashValid = await validateBmffHash(bytes, bmff.hashBytes, {
			exclusions: bmff.exclusions,
			alg: bmff.alg,
		})
	}

	const codes = new Set<LiveVideoStatusCode>()
	if (!hasManifest) codes.add(LiveVideoStatusCode.MANIFEST_INVALID)
	if (!hasLiveVideo) codes.add(LiveVideoStatusCode.ASSERTION_INVALID)
	if (!streamIdValid) codes.add(LiveVideoStatusCode.ASSERTION_INVALID)
	if (!sequenceNumberValid) codes.add(LiveVideoStatusCode.ASSERTION_INVALID)
	if (bmffHashValid === false) codes.add(LiveVideoStatusCode.SEGMENT_INVALID)

	if (!continuityMethod) {
		codes.add(LiveVideoStatusCode.CONTINUITY_METHOD_INVALID)
	} else if (!SUPPORTED_CONTINUITY_METHODS.has(continuityMethod)) {
		codes.add(LiveVideoStatusCode.CONTINUITY_METHOD_INVALID)
	} else if (continuityMethod === CONTINUITY_METHOD_MANIFEST_ID) {
		if (!previousManifestId) {
			codes.add(LiveVideoStatusCode.CONTINUITY_METHOD_INVALID)
		} else if (lastManifestId && normalizeManifestId(previousManifestId) !== normalizeManifestId(lastManifestId)) {
			// §19.7.2: previousManifestId value mismatch → SEGMENT_INVALID
			codes.add(LiveVideoStatusCode.SEGMENT_INVALID)
		}
	}

	const errorCodes = [...codes]

	const currentManifestId = manifest?.activeManifest?.instanceId ?? null

	return {
		result: {
			manifest,
			issuer,
			sequenceNumber,
			previousManifestId,
			streamId,
			continuityMethod,
			bmffHashHex: bmff.hashHex,
			bmffHashValid,
			isValid: errorCodes.length === 0,
			errorCodes,
		},
		nextManifestId: currentManifestId ?? lastManifestId,
		nextState: {
			lastStreamId: streamId ?? state?.lastStreamId,
			lastSequenceNumber: sequenceNumber ?? state?.lastSequenceNumber,
		},
	}
}
