import { readIsoBoxes } from '@svta/cml-iso-bmff'
import { decodeCoseSign1 } from './cose/decodeCoseSign1.ts'
import { findC2paUuidBox, stripJumbfUuidPrefix } from './utils.ts'
import type { JumbfBox } from './jumbf/JumbfBox.ts'
import { parseJumbfBoxes } from './jumbf/parseJumbfBoxes.ts'
import { parseJumbfLabel } from './jumbf/parseJumbfLabel.ts'

const C2PA_SIGNATURE_LABEL = 'c2pa.signature'
const X5CHAIN_COSE_HEADER = 33
const X5CHAIN_LEGACY_HEADER = 'x5chain'

type CoseHeaderRecord = Readonly<Record<number | string, unknown>>

function readX5chain(header: CoseHeaderRecord): unknown {
	return header[X5CHAIN_COSE_HEADER] ?? header[X5CHAIN_LEGACY_HEADER]
}

/**
 * Extracts the full `x5chain` (leaf first) from raw COSE_Sign1 signature bytes.
 *
 * Accepts the integer label 33 and the legacy string label `x5chain`. The integer label wins
 * when both are present.
 *
 * @internal
 */
export function extractCertificateChainFromSignatureBytes(signatureBytes: Uint8Array): Uint8Array[] {
	try {
		const cose = decodeCoseSign1(signatureBytes)
		const x5chain = readX5chain(cose.protectedHeader) ?? readX5chain(cose.unprotectedHeader)
		const certs: unknown[] = Array.isArray(x5chain) ? x5chain : [x5chain]
		const end = certs.findIndex(cert => !(cert instanceof Uint8Array))
		return (end === -1 ? certs : certs.slice(0, end)) as Uint8Array[]
	} catch {
		return []
	}
}

/**
 * Extracts the end-entity certificate from raw COSE_Sign1 signature bytes.
 *
 * @internal
 */
export function extractCertificateFromSignatureBytes(signatureBytes: Uint8Array): Uint8Array | null {
	return extractCertificateChainFromSignatureBytes(signatureBytes)[0] ?? null
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
 * @internal
 */
export function extractManifestCertificate(mp4Bytes: Uint8Array): Uint8Array | null {
	try {
		const boxes = readIsoBoxes(mp4Bytes)
		const uuidBox = findC2paUuidBox(boxes)
		if (!uuidBox) return null

		const rawPayload = uuidBox.view.readData(uuidBox.view.bytesRemaining) as Uint8Array
		const jumbfPayload = stripJumbfUuidPrefix(rawPayload)
		if (!jumbfPayload) return null
		const signatureBytes = findSignatureContentBytes(parseJumbfBoxes(jumbfPayload))
		if (!signatureBytes) return null

		return extractCertificateFromSignatureBytes(signatureBytes)
	} catch {
		return null
	}
}
