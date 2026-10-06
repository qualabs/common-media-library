import { decodeBase64 } from '@svta/cml-utils'
import { parseCertificate, type ParsedCertificate } from '../x509/parseCertificate.ts'
import { bindTrustPolicyState, hashCertificate } from './evaluateCertificateTrust.ts'
import type { TrustPolicy, TrustPolicyOptions } from './TrustPolicy.ts'

const DEFAULT_EKU_OIDS: readonly string[] = [
	'1.3.6.1.4.1.62558.2.1',
	'1.3.6.1.5.5.7.3.4',
	'1.3.6.1.5.5.7.3.36',
]

const PEM_CERTIFICATE_PATTERN = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g
const INLINE_PATTERN = /-----BEGIN|[\r\n]/
const URL_PATTERN = /^https?:\/\//i
const LINE_BREAK_PATTERN = /\r?\n/
const WHITESPACE_PATTERN = /\s/g
const CERT_HASH_PATTERN = /^[A-Za-z0-9+/]{43}=$/
const OID_PATTERN = /^\d+(\.\d+)+$/

type TrustField = keyof TrustPolicyOptions

type ParsedSources = {
	anchors?: ParsedCertificate[]
	allowedHashes?: Set<string>
	ekuOids?: Set<string>
}

function describeSource(source: string): string {
	return INLINE_PATTERN.test(source) ? 'inline content' : `"${source}"`
}

async function readSource(source: string): Promise<string> {
	if (INLINE_PATTERN.test(source)) return source

	if (URL_PATTERN.test(source)) {
		const response = await fetch(source)
		if (!response.ok) throw new Error(`HTTP ${response.status}`)
		return response.text()
	}

	let fs: typeof import('node:fs/promises')
	try {
		fs = await import(/* webpackIgnore: true */ /* @vite-ignore */ 'node:fs/promises')
	}
	catch {
		throw new Error('local paths require Node')
	}
	return fs.readFile(source, 'utf8')
}

function readPemCertificates(text: string): ParsedCertificate[] {
	return [...text.matchAll(PEM_CERTIFICATE_PATTERN)].map((match, i) => {
		let cert: ParsedCertificate | null = null
		try {
			cert = parseCertificate(decodeBase64(match[1].replace(WHITESPACE_PATTERN, '')))
		}
		catch {
			cert = null
		}
		if (!cert) throw new Error(`certificate ${i + 1} does not parse`)
		return cert
	})
}

async function parseAllowedList(text: string): Promise<Set<string>> {
	const hashes = new Set<string>()
	let insidePem = false
	for (const rawLine of text.split(LINE_BREAK_PATTERN)) {
		const line = rawLine.trim()
		if (line.includes('-----BEGIN')) insidePem = true
		if (!insidePem && CERT_HASH_PATTERN.test(line)) hashes.add(line)
		if (line.includes('-----END')) insidePem = false
	}
	for (const cert of readPemCertificates(text)) hashes.add(await hashCertificate(cert.der))
	return hashes
}

function parseTrustConfig(text: string): Set<string> {
	const oids = new Set<string>()
	for (const rawLine of text.split(LINE_BREAK_PATTERN)) {
		const line = rawLine.split('#')[0].trim()
		if (OID_PATTERN.test(line)) oids.add(line)
	}
	return oids
}

async function loadField(field: TrustField, source: string, parsed: ParsedSources): Promise<void> {
	const text = await readSource(source)
	let count: number
	switch (field) {
		case 'trustAnchors':
			parsed.anchors = readPemCertificates(text)
			count = parsed.anchors.length
			break
		case 'allowedList':
			parsed.allowedHashes = await parseAllowedList(text)
			count = parsed.allowedHashes.size
			break
		case 'trustConfig':
			parsed.ekuOids = parseTrustConfig(text)
			count = parsed.ekuOids.size
			break
	}
	if (count === 0) throw new Error('no usable entries')
}

/**
 * Loads and parses trust sources once, for use in every validation call.
 *
 * The function never rejects because of a trust source. If a source fails to load or has no
 * usable entries, the returned policy lists the failure in `loadErrors` and trusts no certificate.
 * Every result that such a policy evaluates is not valid, with `signingCredential.untrusted`.
 *
 * Without `trustConfig`, the policy accepts the EKUs of C2PA 2.4 §14.4.1:
 * `c2pa-kp-claimSigning`, `id-kp-emailProtection`, and `id-kp-documentSigning`.
 *
 * @param options - Trust sources. Each one is inline content, a URL, or a local file path.
 * @returns An immutable trust policy
 *
 * @example
 * {@includeCode ../../test/trust/createTrustPolicy.test.ts#example}
 *
 * @public
 */
export async function createTrustPolicy(options: TrustPolicyOptions = {}): Promise<TrustPolicy> {
	const parsed: ParsedSources = {}
	const fields = (['trustAnchors', 'allowedList', 'trustConfig'] as const).filter(field => options[field] !== undefined)

	const results = await Promise.allSettled(fields.map(field => loadField(field, options[field] as string, parsed)))

	const loadErrors: string[] = []
	results.forEach((result, i) => {
		if (result.status === 'rejected') {
			const field = fields[i]
			const reason = result.reason instanceof Error ? result.reason.message : String(result.reason)
			loadErrors.push(`${field}: cannot use ${describeSource(options[field] as string)}: ${reason}`)
		}
	})

	const policy: TrustPolicy = Object.freeze({ loadErrors: Object.freeze(loadErrors) })
	if (loadErrors.length === 0) {
		bindTrustPolicyState(policy, {
			anchors: parsed.anchors ?? [],
			allowedHashes: parsed.allowedHashes ?? new Set(),
			ekuOids: parsed.ekuOids ?? new Set(DEFAULT_EKU_OIDS),
			cache: new Map(),
		})
	}
	return policy
}
