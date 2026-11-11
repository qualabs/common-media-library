import { readFileSync } from 'node:fs'

const PKI_ENTRY_PATTERN = /^# (\S+)\n(-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----)/gm
const PEM_BODY_PATTERN = /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/

const PKI_PATH: string = new URL('../fixtures/trust/pki.pem', import.meta.url).pathname

const PKI: ReadonlyMap<string, string> = new Map(
	[...readFileSync(PKI_PATH, 'utf8').matchAll(PKI_ENTRY_PATTERN)].map(([, name, block]) => [
		name,
		block,
	]),
)

/** PEM block of a certificate or key in `pki.pem`. */
export function pem(name: string): string {
	const block = PKI.get(name)
	if (!block) throw new Error(`No ${name} in pki.pem`)
	return block
}

/** DER bytes of a certificate or key in `pki.pem`. */
export function loadDer(name: string): Uint8Array {
	const body = PEM_BODY_PATTERN.exec(pem(name))?.[1] ?? ''
	return new Uint8Array(Buffer.from(body.replace(/\s/g, ''), 'base64'))
}

/** Trust config that adds a vendor EKU, in the c2pa-rs format. */
export const VENDOR_EKU_CONFIG = `// Vendor signing
1.3.6.1.4.1.99999.1
`
