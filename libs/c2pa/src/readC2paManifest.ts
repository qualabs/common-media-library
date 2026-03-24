import { readIsoBoxes } from '@svta/cml-iso-bmff'
import { decode } from 'cbor-x'
import type { C2paAssertion } from './C2paAssertion.ts'
import type { C2paManifest, C2paManifestStore } from './C2paManifest.ts'
import { decodeCoseSign1 } from './cose/decodeCoseSign1.ts'
import type { JumbfBox } from './jumbf/JumbfBox.ts'
import { parseJumbfBoxes } from './jumbf/parseJumbfBoxes.ts'
import { parseJumbfLabel } from './jumbf/parseJumbfLabel.ts'
import { stripJumbfUuidPrefix } from './utils.ts'
import { extractCertificateInfo } from './x509/extractCertificateInfo.ts'

// C2PA manifest store UUID per C2PA specification
const C2PA_MANIFEST_UUID: readonly number[] = [
	0xd8, 0xfe, 0xc3, 0xd6, 0x1a, 0x96, 0x4f, 0x32,
	0xa0, 0xf6, 0xf3, 0xec, 0xf9, 0x6c, 0x10, 0xea,
]

// JUMBF UUID per ISO 19566-5 (used by c2pa-rs and other JUMBF-compliant tools)
const JUMBF_UUID: readonly number[] = [
	0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c,
	0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
]

function matchesUuid(usertype: readonly number[], expected: readonly number[]): boolean {
	return usertype.length === expected.length && expected.every((byte, i) => byte === usertype[i])
}

function isC2paUuid(usertype: readonly number[]): boolean {
	return matchesUuid(usertype, C2PA_MANIFEST_UUID) || matchesUuid(usertype, JUMBF_UUID)
}


function resolveManifestBoxes(jumbfBoxes: JumbfBox[]): JumbfBox[] {
	// Skip jumd description boxes — they contain labels, not manifest content
	const contentBoxes = jumbfBoxes.filter(b => b.type !== 'jumd')

	// Single jumb wrapping — unwrap one level and recurse
	// This handles: store jumb → manifest jumb → claim/assertions/signature
	if (contentBoxes.length === 1 && contentBoxes[0]!.type === 'jumb') {
		return resolveManifestBoxes(parseJumbfBoxes(contentBoxes[0]!.data))
	}

	// Multiple content boxes — these are the manifest parts (claim, assertions, signature)
	return jumbfBoxes
}

function extractManifestLabel(jumbfBoxes: JumbfBox[]): string | null {
	// Navigate: store jumb → manifest jumb → jumd label
	for (const box of jumbfBoxes) {
		if (box.type !== 'jumb') continue
		const inner = parseJumbfBoxes(box.data)
		for (const child of inner) {
			if (child.type !== 'jumb') continue
			const childInner = parseJumbfBoxes(child.data)
			const jumd = childInner.find(b => b.type === 'jumd')
			if (jumd) {
				const label = parseJumbfLabel(jumd.data)
				if (label) return label
			}
		}
	}
	return null
}

function parseAssertions(assertionStoreBoxes: JumbfBox[]): C2paAssertion[] {
	const assertions: C2paAssertion[] = []

	for (const box of assertionStoreBoxes) {
		if (box.type !== 'jumb') continue
		const inner = parseJumbfBoxes(box.data)

		const jumd = inner.find(b => b.type === 'jumd')
		if (!jumd) continue

		const label = parseJumbfLabel(jumd.data)
		if (!label) continue

		const contentBox = inner.find(
			b => b.type === 'cbor' || b.type === 'json' || b.type === 'jumc' || b.type === 'jp2c' || b.type === 'bidb',
		)

		let data: unknown = null
		if (contentBox) {
			if (contentBox.type === 'cbor') {
				try { data = decode(contentBox.data) as unknown } catch { data = contentBox.data }
			}
			else if (contentBox.type === 'json') {
				try { data = JSON.parse(new TextDecoder().decode(contentBox.data)) as unknown } catch { data = contentBox.data }
			}
			else {
				data = contentBox.data
			}
		}

		assertions.push({ label, data })
	}

	return assertions
}

/**
 * Reads a C2PA manifest store from raw BMFF bytes.
 *
 * Locates the C2PA UUID box (`d8fec3d6-1a96-4f32-a0f6-f3ecf96c10ea`), navigates
 * the JUMBF manifest store structure (ISO 19566-5), and returns the parsed active
 * manifest with its claims, assertions, and signature information.
 *
 * This function performs structural parsing only. It does not verify the
 * cryptographic signature of the claim.
 *
 * @param bytes - Raw BMFF bytes (e.g. an MP4 init segment or media segment)
 * @returns The parsed C2PA manifest store
 * @throws {Error} If no C2PA UUID box is found, or the JUMBF structure is invalid
 *
 * @example
 * {@includeCode ../test/readC2paManifest.test.ts#example}
 *
 * @public
 */
export function readC2paManifest(bytes: Uint8Array): C2paManifestStore {
	const boxes = readIsoBoxes(bytes)
	// eslint-disable-next-line @typescript-eslint/no-explicit-any -- uuid boxes are not in the cml-iso-bmff type union
	const uuidBox = (boxes as any[]).find(
		(box: { type: string; usertype?: number[] }) => box.type === 'uuid' && isC2paUuid(box.usertype ?? []),
	)

	if (!uuidBox) {
		throw new Error('No C2PA UUID box found in the provided bytes')
	}

	const rawPayload = uuidBox.view.readData(uuidBox.view.bytesRemaining) as Uint8Array
	const jumbfPayload = stripJumbfUuidPrefix(rawPayload)
	const jumbfBoxes = parseJumbfBoxes(jumbfPayload)

	if (jumbfBoxes.length === 0) {
		throw new Error('No JUMBF boxes found in C2PA UUID box')
	}

	const manifestLabel = extractManifestLabel(jumbfBoxes)
	const manifestBoxes = resolveManifestBoxes(jumbfBoxes)

	let claimData: Record<string, unknown> | null = null
	let assertions: C2paAssertion[] = []
	let signatureBytes: Uint8Array | null = null

	for (const box of manifestBoxes) {
		if (box.type !== 'jumb') continue

		const inner = parseJumbfBoxes(box.data)
		const jumd = inner.find(b => b.type === 'jumd')
		if (!jumd) continue

		const label = parseJumbfLabel(jumd.data)
		if (!label) continue

		if (label === 'c2pa.claim' || label === 'c2pa.claim.v2') {
			const contentBox = inner.find(b => b.type === 'cbor')
			if (contentBox) {
				try { claimData = decode(contentBox.data) as Record<string, unknown> } catch { /* malformed claim — continue */ }
			}
		}
		else if (label === 'c2pa.assertions') {
			assertions = parseAssertions(inner)
		}
		else if (label === 'c2pa.signature') {
			const contentBox = inner.find(b => b.type === 'cbor' || b.type === 'jumc')
			if (contentBox) signatureBytes = contentBox.data
		}
	}

	let issuer: string | null = null
	let signingTime: string | null = null

	if (signatureBytes) {
		try {
			const cose = decodeCoseSign1(signatureBytes)
			const x5chain = (cose.protectedHeader[33] ?? cose.unprotectedHeader[33]) as Uint8Array | Uint8Array[] | null | undefined
			if (x5chain) {
				const certDER = Array.isArray(x5chain) ? x5chain[0] : x5chain
				if (certDER instanceof Uint8Array) {
					const certInfo = extractCertificateInfo(certDER)
					if (certInfo) {
						issuer = certInfo.issuer
						signingTime = certInfo.notBefore
					}
				}
			}
		}
		catch { /* signature parsing failed — continue without signature info */ }
	}

	const instanceId = (claimData?.['instanceID'] ?? claimData?.['instance_id'] ?? null) as string | null
	const claimGenerator = (claimData?.['claim_generator'] ?? claimData?.['claimGenerator'] ?? null) as string | null
	const label =
		manifestLabel ??
		(claimData?.['dc:title'] as string | undefined) ??
		(claimData?.['title'] as string | undefined) ??
		instanceId ??
		'unknown'

	const activeManifest: C2paManifest = {
		label,
		instanceId,
		claimGenerator,
		signatureInfo: { issuer, time: signingTime },
		assertions,
	}

	return { activeManifest }
}
