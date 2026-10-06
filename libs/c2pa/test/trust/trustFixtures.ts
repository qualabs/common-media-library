import { readFileSync } from 'node:fs'

const PKI_ENTRY_PATTERN = /^# (\S+)\n(-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----)/gm
const PEM_BODY_PATTERN = /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/

export const PKI_PATH: string = new URL('../fixtures/trust/pki.pem', import.meta.url).pathname

const PKI: ReadonlyMap<string, string> = new Map(
	[...readFileSync(PKI_PATH, 'utf8').matchAll(PKI_ENTRY_PATTERN)].map(([, name, block]) => [name, block]),
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

export async function certHash(der: Uint8Array): Promise<string> {
	return Buffer.from(await crypto.subtle.digest('SHA-256', der as Uint8Array<ArrayBuffer>)).toString('base64')
}

/** Allowed list with one PEM block, one hash line, and lines the parser must skip. */
export async function allowedListFixture(): Promise<string> {
	return [
		'# Allowed signers',
		pem('self-signed-leaf'),
		await certHash(loadDer('leaf-ec-expired')),
		'not-a-hash',
		'QUJD',
		'',
	].join('\n')
}

/** Trust config that accepts only c2pa-kp-claimSigning. */
export const CLAIM_SIGNING_ONLY_CONFIG = `// C2PA Signing
1.3.6.1.4.1.62558.2.1

# lines that are not OIDs are ignored
not.an.oid
`
