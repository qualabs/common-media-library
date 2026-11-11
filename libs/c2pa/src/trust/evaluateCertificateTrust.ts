import { encodeBase64 } from '@svta/cml-utils'
import { C2paStatusCode } from '../C2paStatusCode.ts'
import { hashesEqual } from '../utils.ts'
import {
	ML_DSA_OIDS,
	OID_EC_PUBLIC_KEY,
	OID_ED25519,
	OID_RSA_ENCRYPTION,
	OID_RSASSA_PSS,
	parseCertificate,
	type ParsedCertificate,
} from '../x509/parseCertificate.ts'
import {
	isAllowedSignatureAlgorithm,
	verifyCertificateSignature,
	type CertificateSignatureCheck,
} from '../x509/verifyCertificateSignature.ts'
import type { TrustFailure, TrustPolicy } from './TrustPolicy.ts'

const EKU_ANY = '2.5.29.37.0'
const EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8'
const EKU_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9'
const MIN_RSA_MODULUS_BITS = 2048
const X509_VERSION_3 = 3
const MAX_CHAIN_LENGTH = 10
const MAX_CACHED_CHAINS = 64

type TrustWindow = {
	readonly notBefore: number
	readonly notAfter: number
}

const ALWAYS: TrustWindow = { notBefore: -Infinity, notAfter: Infinity }

// The result of every check except the time. The anchor window is the time bound of the trust
// anchor configuration (§15.7). The path window covers the signing certificate and its CA
// certificates (§15.8.2).
type ChainVerdict =
	| { readonly anchor: TrustWindow; readonly path: TrustWindow }
	| Exclude<TrustFailure, typeof C2paStatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY>

// A verdict is definitive unless the runtime could not complete the checks.
type CachedChain = {
	readonly chain: readonly Uint8Array[]
	readonly result: Promise<{ readonly verdict: ChainVerdict; readonly isDefinitive: boolean }>
}

/**
 * Parsed contents of a trust policy.
 *
 * @internal
 */
export type TrustPolicyState = {
	readonly anchors: readonly ParsedCertificate[]
	readonly allowedHashes: ReadonlySet<string>
	readonly ekuOids: ReadonlySet<string>
	readonly validationTime: () => Date
	readonly clockTolerance: number
}

/**
 * Returns the base64 SHA-256 hash of a DER certificate, the format of allowed-list entries.
 *
 * @internal
 */
export async function hashCertificate(der: Uint8Array): Promise<string> {
	return encodeBase64(
		new Uint8Array(await crypto.subtle.digest('SHA-256', der as Uint8Array<ArrayBuffer>)),
	)
}

function windowOf(certs: readonly ParsedCertificate[]): TrustWindow {
	return {
		notBefore: Math.max(...certs.map(cert => cert.notBefore.getTime())),
		notAfter: Math.min(...certs.map(cert => cert.notAfter.getTime())),
	}
}

function isSelfIssued(cert: ParsedCertificate): boolean {
	return hashesEqual(cert.issuer, cert.subject)
}

// C2PA 2.4 §14.5.1.1: the requirements for every certificate outside the private credential store.
function meetsCommonProfile(cert: ParsedCertificate): boolean {
	return (
		cert.version === X509_VERSION_3 &&
		!cert.hasUniqueIds &&
		(cert.hasAuthorityKeyId || isSelfIssued(cert))
	)
}

function canIssue(cert: ParsedCertificate): boolean {
	return meetsCommonProfile(cert) && cert.isCa && cert.keyCertSign && cert.hasSubjectKeyId
}

// C2PA 2.5 §13.5.1.1 limits the key requirements to claim signing certificates. C2PA 2.4 applied them to all certificates.
function meetsKeyRequirements(cert: ParsedCertificate): boolean {
	switch (cert.keyAlgorithm) {
		case OID_EC_PUBLIC_KEY:
			return cert.keyCurve !== null
		case OID_RSA_ENCRYPTION:
		case OID_RSASSA_PSS:
			return cert.rsaModulusBits !== null && cert.rsaModulusBits >= MIN_RSA_MODULUS_BITS
		case OID_ED25519:
			return true
		default:
			return ML_DSA_OIDS.has(cert.keyAlgorithm)
	}
}

// C2PA 2.4 §14.5.1.1: the requirements for every claim signing certificate, allowed-list entries included.
function meetsClaimSigningProfile(leaf: ParsedCertificate): boolean {
	return meetsKeyRequirements(leaf) && isAllowedSignatureAlgorithm(leaf)
}

// C2PA 2.4 §14.5.1.1: the additional requirements for a signing certificate that chains to an anchor.
function meetsSignerProfile(leaf: ParsedCertificate): boolean {
	if (
		!meetsClaimSigningProfile(leaf) ||
		!meetsCommonProfile(leaf) ||
		leaf.hasUnknownCriticalExtension
	)
		return false
	if (leaf.isCa || leaf.keyCertSign || !leaf.digitalSignature) return false

	const ekus = leaf.ekuOids
	if (ekus.includes(EKU_ANY)) return false
	const isTimeStampingOrOcsp = ekus.includes(EKU_TIME_STAMPING) || ekus.includes(EKU_OCSP_SIGNING)
	return !isTimeStampingOrOcsp || ekus.length === 1
}

// RFC 5280 §6.1: a path with an unknown critical extension or a broken pathLenConstraint fails.
function meetsPathConstraints(path: readonly ParsedCertificate[]): boolean {
	return path.every(
		(cert, i) =>
			!cert.hasUnknownCriticalExtension &&
			(i === 0 || cert.pathLength === null || i - 1 <= cert.pathLength),
	)
}

async function isIssuedBy(
	child: ParsedCertificate,
	parent: ParsedCertificate,
): Promise<CertificateSignatureCheck> {
	if (!canIssue(parent) || !hashesEqual(child.issuer, parent.subject)) return 'failed'
	return verifyCertificateSignature(child, parent)
}

type AnchorPath = { readonly path: ParsedCertificate[]; readonly anchor: ParsedCertificate }

async function buildAnchorPath(
	chain: readonly ParsedCertificate[],
	anchors: readonly ParsedCertificate[],
): Promise<AnchorPath | 'untrusted' | 'unsupported'> {
	for (let i = 0; i < chain.length; i++) {
		const current = chain[i]
		if (anchors.some(anchor => hashesEqual(anchor.der, current.der)))
			return { path: chain.slice(0, i + 1), anchor: current }

		const parent = chain[i + 1]
		if (parent) {
			const check = await isIssuedBy(current, parent)
			if (check === 'unsupported') return check
			if (check !== 'verified') return 'untrusted'
			continue
		}

		let unsupported = false
		for (const anchor of anchors) {
			const check = await isIssuedBy(current, anchor)
			if (check === 'verified') return { path: [...chain, anchor], anchor }
			if (check === 'unsupported') unsupported = true
		}
		return unsupported ? 'unsupported' : 'untrusted'
	}
	return 'untrusted'
}

async function evaluateChain(
	state: TrustPolicyState,
	chain: readonly Uint8Array[],
): Promise<ChainVerdict> {
	const parsed: ParsedCertificate[] = []
	for (const der of chain) {
		const cert = parseCertificate(der)
		if (!cert) return C2paStatusCode.SIGNING_CREDENTIAL_INVALID
		parsed.push(cert)
	}
	const leaf = parsed[0]

	if (state.allowedHashes.size > 0 && state.allowedHashes.has(await hashCertificate(leaf.der))) {
		return meetsClaimSigningProfile(leaf)
			? { anchor: ALWAYS, path: windowOf([leaf]) }
			: C2paStatusCode.SIGNING_CREDENTIAL_INVALID
	}

	if (!meetsSignerProfile(leaf) || !leaf.ekuOids.some(oid => state.ekuOids.has(oid)))
		return C2paStatusCode.SIGNING_CREDENTIAL_INVALID

	const found = await buildAnchorPath(parsed, state.anchors)
	if (found === 'unsupported') return C2paStatusCode.ALGORITHM_UNSUPPORTED
	if (found === 'untrusted' || !meetsPathConstraints(found.path))
		return C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED

	const { path, anchor } = found
	if (path.length === 1) return { anchor: ALWAYS, path: windowOf(path) }
	return { anchor: windowOf([anchor]), path: windowOf(path.slice(0, -1)) }
}

function chainsEqual(a: readonly Uint8Array[], b: readonly Uint8Array[]): boolean {
	return a.length === b.length && a.every((der, i) => hashesEqual(der, b[i]))
}

/**
 * Creates the `evaluate` function of a trust policy.
 *
 * The leaf is trusted in two cases. In the first case, its hash is on the allowed list. In the
 * second case, the chain verifies up to a trust anchor. The leaf must also meet the certificate
 * profile of C2PA 2.4 §14.5.1.1 and carry an accepted EKU. In both cases, the signing
 * certificate and its CA certificates must be within their validity period.
 *
 * The function caches the verification of the 64 chains that it used last. It compares the
 * validity periods with the validation time at every call.
 *
 * @param state - Parsed trust sources and time settings
 * @returns The `evaluate` function of a {@link TrustPolicy}
 *
 * @internal
 */
export function createChainEvaluator(state: TrustPolicyState): TrustPolicy['evaluate'] {
	const cache: CachedChain[] = []

	return async chain => {
		if (chain.length === 0 || chain.length > MAX_CHAIN_LENGTH)
			return C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED

		const index = cache.findIndex(entry => chainsEqual(entry.chain, chain))
		// A copy, so the cache does not keep the segment that holds the x5chain.
		const copy = index === -1 ? chain.map(der => der.slice()) : []
		const entry: CachedChain =
			index === -1
				? {
						chain: copy,
						result: evaluateChain(state, copy).then(
							verdict => ({
								verdict,
								isDefinitive: verdict !== C2paStatusCode.ALGORITHM_UNSUPPORTED,
							}),
							() => ({ verdict: C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED, isDefinitive: false }),
						),
					}
				: cache.splice(index, 1)[0]
		cache.push(entry)
		if (cache.length > MAX_CACHED_CHAINS) cache.shift()

		const { verdict, isDefinitive } = await entry.result
		if (!isDefinitive && cache.includes(entry)) cache.splice(cache.indexOf(entry), 1)
		if (typeof verdict === 'string') return verdict

		const now = state.validationTime().getTime()
		const tolerance = state.clockTolerance
		const isInside = (window: TrustWindow): boolean =>
			window.notBefore - tolerance <= now && now <= window.notAfter + tolerance
		if (!isInside(verdict.anchor)) return C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED
		if (!isInside(verdict.path)) return C2paStatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY
		return null
	}
}
