import { decodeBase64 } from '@svta/cml-utils'
import { parseCertificate, type ParsedCertificate } from '../x509/parseCertificate.ts'
import { createChainEvaluator, hashCertificate } from './evaluateCertificateTrust.ts'
import type { TrustPolicy, TrustPolicyOptions } from './TrustPolicy.ts'

const DEFAULT_EKU_OIDS: readonly string[] = [
	'1.3.6.1.4.1.62558.2.1',
	'1.3.6.1.5.5.7.3.4',
	'1.3.6.1.5.5.7.3.36',
]

const PEM_CERTIFICATE_PATTERN =
	/-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]*)-----END CERTIFICATE-----/g
const LINE_BREAK_PATTERN = /\r?\n/
const NOT_LINE_BREAK_PATTERN = /[^\n]/g
const WHITESPACE_PATTERN = /\s/g
const HASH_COMMENT_PATTERN = /#.*$/
const CERT_HASH_PATTERN = /^[A-Za-z0-9+/]{43}=$/
const OID_PATTERN = /^\d+(\.\d+)+$/
const PEM_BEGIN_MARKER = '-----BEGIN CERTIFICATE-----'
const SOURCE_HINT = 'Pass the text of the source, not a URL or a file path.'

function readPemCertificates(field: string, text: string, errors: string[]): ParsedCertificate[] {
	const certs: ParsedCertificate[] = []
	let index = 0
	for (const match of text.matchAll(PEM_CERTIFICATE_PATTERN)) {
		index++
		let cert: ParsedCertificate | null = null
		try {
			cert = parseCertificate(decodeBase64(match[1].replace(WHITESPACE_PATTERN, '')))
		} catch {
			cert = null
		}
		if (cert) certs.push(cert)
		else errors.push(`${field}: PEM certificate ${index} does not parse`)
	}
	if (text.split(PEM_BEGIN_MARKER).length - 1 > index)
		errors.push(
			`${field}: a PEM certificate block has no END line or has characters that are not base64`,
		)
	return certs
}

// Returns the lines that are not PEM blocks, blank lines, or comments, with their line numbers.
function readEntryLines(text: string): { readonly line: number; readonly entry: string }[] {
	const withoutPem = text.replace(PEM_CERTIFICATE_PATTERN, block =>
		block.replace(NOT_LINE_BREAK_PATTERN, ''),
	)
	return withoutPem
		.split(LINE_BREAK_PATTERN)
		.map((raw, i) => ({ line: i + 1, entry: raw.replace(HASH_COMMENT_PATTERN, '').trim() }))
		.filter(({ entry }) => entry !== '' && !entry.startsWith('//'))
}

async function parseAllowedList(text: string, errors: string[]): Promise<Set<string>> {
	const hashes = new Set<string>()
	for (const { line, entry } of readEntryLines(text)) {
		if (CERT_HASH_PATTERN.test(entry)) hashes.add(entry)
		else errors.push(`allowedList: line ${line} is not a PEM certificate or a base64 SHA-256 hash`)
	}
	for (const cert of readPemCertificates('allowedList', text, errors))
		hashes.add(await hashCertificate(cert.der))
	return hashes
}

function parseTrustConfig(text: string, errors: string[]): Set<string> {
	const oids = new Set<string>()
	for (const { line, entry } of readEntryLines(text)) {
		if (OID_PATTERN.test(entry)) oids.add(entry)
		else errors.push(`trustConfig: line ${line} is not an OID`)
	}
	return oids
}

/**
 * Parses trust sources once, for use in every validation call.
 *
 * Every source is text: PEM certificates for `trustAnchors`, PEM certificates or base64 SHA-256
 * hashes for `allowedList`, and OIDs for `trustConfig`. Lines that start with `#` or `//` are
 * comments. The policy accepts the EKUs of C2PA 2.4 §14.4.1 and the EKUs of `trustConfig`.
 * The default EKUs are `c2pa-kp-claimSigning`, `id-kp-emailProtection`, and `id-kp-documentSigning`.
 *
 * @param options - Trust sources and time settings
 * @returns An immutable trust policy
 * @throws If neither `trustAnchors` nor `allowedList` is present, or if a source has an entry that does not parse or has no entries
 *
 * @example
 * {@includeCode ../../test/trust/createTrustPolicy.test.ts#example}
 *
 * @public
 */
export async function createTrustPolicy(options: TrustPolicyOptions): Promise<TrustPolicy> {
	const { trustAnchors, allowedList, trustConfig } = options
	if (trustAnchors === undefined && allowedList === undefined)
		throw new Error('createTrustPolicy: options need trustAnchors, allowedList, or both')

	const errors: string[] = []
	let anchors: ParsedCertificate[] = []
	if (trustAnchors !== undefined) {
		anchors = readPemCertificates('trustAnchors', trustAnchors, errors)
		if (anchors.length === 0 && errors.length === 0)
			errors.push(`trustAnchors: no PEM certificate found. ${SOURCE_HINT}`)
	}

	let allowedHashes = new Set<string>()
	if (allowedList !== undefined) {
		const before = errors.length
		allowedHashes = await parseAllowedList(allowedList, errors)
		if (allowedHashes.size === 0 && errors.length === before)
			errors.push(`allowedList: no PEM certificate or hash found. ${SOURCE_HINT}`)
	}

	const ekuOids = new Set(DEFAULT_EKU_OIDS)
	if (trustConfig !== undefined)
		for (const oid of parseTrustConfig(trustConfig, errors)) ekuOids.add(oid)

	if (errors.length > 0) throw new Error(`createTrustPolicy: ${errors.join('. ')}`)

	return Object.freeze({
		evaluate: createChainEvaluator({
			anchors,
			allowedHashes,
			ekuOids,
			validationTime: options.validationTime ?? (() => new Date()),
			clockTolerance: options.clockTolerance ?? 0,
		}),
	})
}
