import { readIsoBoxes } from '@svta/cml-iso-bmff'
import { decodeCoseSign1 } from './cose/decodeCoseSign1.ts'
import { stripJumbfUuidPrefix } from './utils.ts'
import type { JumbfBox } from './jumbf/JumbfBox.ts'
import { parseJumbfBoxes } from './jumbf/parseJumbfBoxes.ts'
import { parseJumbfLabel } from './jumbf/parseJumbfLabel.ts'

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

const C2PA_SIGNATURE_LABEL = 'c2pa.signature'
const X5CHAIN_COSE_HEADER = 33

function matchesUuid(usertype: readonly number[], expected: readonly number[]): boolean {
	return usertype.length === expected.length && expected.every((b, i) => b === usertype[i])
}

function isC2paUuid(usertype: readonly number[]): boolean {
	return matchesUuid(usertype, C2PA_MANIFEST_UUID) || matchesUuid(usertype, JUMBF_UUID)
}

function findSignatureContentBytes(boxes: JumbfBox[]): Uint8Array | null {
	for (const box of boxes) {
		if (box.type !== 'jumb') continue
		const inner = parseJumbfBoxes(box.data)
		const jumd = inner.find(b => b.type === 'jumd')

		if (jumd && parseJumbfLabel(jumd.data) === C2PA_SIGNATURE_LABEL) {
			const content = inner.find(b => b.type === 'cbor' || b.type === 'jumc')
			return content?.data ?? null
		}

		const nested = findSignatureContentBytes(inner)
		if (nested) return nested
	}
	return null
}

/**
 * Extracts the end-entity certificate (DER-encoded) from the C2PA claim signature
 * embedded in a BMFF file.
 *
 * Navigates the JUMBF structure inside the C2PA UUID box to locate the
 * `c2pa.signature` entry, decodes the `COSE_Sign1`, and returns the first
 * certificate from the `x5chain` (COSE protected header label 33).
 *
 * @param mp4Bytes - Raw BMFF bytes (e.g. an MP4 init segment)
 * @returns DER-encoded certificate bytes, or `null` if not found or on any error
 *
 * @example
 * {@includeCode ../test/c2pa/extractManifestCertificate.test.ts#example}
 *
 * @public
 */
export function extractManifestCertificate(mp4Bytes: Uint8Array): Uint8Array | null {
	try {
		const boxes = readIsoBoxes(mp4Bytes)
		// eslint-disable-next-line @typescript-eslint/no-explicit-any -- uuid boxes are not in the cml-iso-bmff type union
		const uuidBox = (boxes as any[]).find(
			(box: { type: string; usertype?: number[] }) => box.type === 'uuid' && isC2paUuid(box.usertype ?? []),
		)
		if (!uuidBox) return null

		const rawPayload = uuidBox.view.readData(uuidBox.view.bytesRemaining) as Uint8Array
		const jumbfPayload = stripJumbfUuidPrefix(rawPayload)
		const signatureBytes = findSignatureContentBytes(parseJumbfBoxes(jumbfPayload))
		if (!signatureBytes) return null

		const cose = decodeCoseSign1(signatureBytes)
		const x5chain = (cose.protectedHeader[X5CHAIN_COSE_HEADER] ??
			cose.unprotectedHeader[X5CHAIN_COSE_HEADER]) as Uint8Array | Uint8Array[] | null | undefined
		if (!x5chain) return null

		const certDER = Array.isArray(x5chain) ? x5chain[0] : x5chain
		return certDER instanceof Uint8Array ? certDER : null
	} catch {
		return null
	}
}
