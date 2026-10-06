import { encodeBase64 } from '@svta/cml-utils'
import { C2paStatusCode } from '../C2paStatusCode.ts'
import type { ManifestIntegrity } from '../claim/validateManifestIntegrity.ts'
import { hashesEqual } from '../utils.ts'
import { OID_EC_PUBLIC_KEY, parseCertificate, type ParsedCertificate } from '../x509/parseCertificate.ts'
import { verifyCertificateSignature } from '../x509/verifyCertificateSignature.ts'
import type { TrustPolicy } from './TrustPolicy.ts'

const EKU_ANY = '2.5.29.37.0'
const EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8'
const EKU_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9'
const MIN_RSA_MODULUS_BITS = 2048
const X509_VERSION_3 = 3
const MAX_CACHED_CHAINS = 64

/**
 * The time range in which a verified chain is trusted, in milliseconds since the epoch.
 *
 * @internal
 */
export type TrustWindow = {
	readonly notBefore: number
	readonly notAfter: number
}

const ALWAYS: TrustWindow = { notBefore: -Infinity, notAfter: Infinity }

/**
 * Why a trust policy rejects a signing credential (§15.7).
 *
 * @internal
 */
export type CredentialFailure = typeof C2paStatusCode.SIGNING_CREDENTIAL_INVALID | typeof C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED

/**
 * Parsed contents of a trust policy that loaded without errors.
 *
 * @internal
 */
export type TrustPolicyState = {
	readonly anchors: readonly ParsedCertificate[]
	readonly allowedHashes: ReadonlySet<string>
	readonly ekuOids: ReadonlySet<string>
	readonly cache: Map<string, Promise<TrustWindow | CredentialFailure>>
}

const POLICY_STATES = /* @__PURE__ */ new WeakMap<TrustPolicy, TrustPolicyState>()

/**
 * Attaches the parsed state to a policy created by `createTrustPolicy`.
 *
 * @internal
 */
export function bindTrustPolicyState(policy: TrustPolicy, state: TrustPolicyState): void {
	POLICY_STATES.set(policy, state)
}

/**
 * Returns the base64 SHA-256 hash of a DER certificate, the format of allowed-list entries.
 *
 * @internal
 */
export async function hashCertificate(der: Uint8Array): Promise<string> {
	return encodeBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', der as Uint8Array<ArrayBuffer>)))
}

function canIssue(cert: ParsedCertificate): boolean {
	return cert.isCa && cert.keyCertSign
}

// C2PA 2.4 §14.5.1.1: key requirements for all certificates, allowed-list entries included.
function meetsKeyRequirements(cert: ParsedCertificate): boolean {
	if (cert.keyAlgorithm === OID_EC_PUBLIC_KEY && cert.keyCurve === null) return false
	return cert.rsaModulusBits === null || cert.rsaModulusBits >= MIN_RSA_MODULUS_BITS
}

// C2PA 2.4 §14.5.1.1: the requirements for a certificate that signs claims.
function meetsSignerProfile(leaf: ParsedCertificate): boolean {
	if (!meetsKeyRequirements(leaf) || leaf.version !== X509_VERSION_3 || leaf.hasUniqueIds || leaf.hasUnknownCriticalExtension) return false
	if (leaf.isCa || leaf.keyCertSign || !leaf.digitalSignature) return false
	if (!leaf.hasAuthorityKeyId && !hashesEqual(leaf.issuer, leaf.subject)) return false

	const ekus = leaf.ekuOids
	if (ekus.includes(EKU_ANY)) return false
	const isTimeStampingOrOcsp = ekus.includes(EKU_TIME_STAMPING) || ekus.includes(EKU_OCSP_SIGNING)
	return !isTimeStampingOrOcsp || ekus.length === 1
}

// RFC 5280 §6.1: a path with an unknown critical extension or a broken pathLenConstraint fails.
function meetsPathConstraints(path: readonly ParsedCertificate[]): boolean {
	return path.every((cert, i) =>
		!cert.hasUnknownCriticalExtension && (i === 0 || cert.pathLength === null || i - 1 <= cert.pathLength))
}

async function isIssuedBy(child: ParsedCertificate, parent: ParsedCertificate): Promise<boolean> {
	return canIssue(parent) && hashesEqual(child.issuer, parent.subject) && verifyCertificateSignature(child, parent)
}

async function buildAnchorPath(chain: readonly ParsedCertificate[], anchors: readonly ParsedCertificate[]): Promise<ParsedCertificate[] | null> {
	for (let i = 0; i < chain.length; i++) {
		const current = chain[i]
		if (anchors.some(anchor => hashesEqual(anchor.der, current.der))) return chain.slice(0, i + 1)

		const parent = chain[i + 1]
		if (parent) {
			if (!await isIssuedBy(current, parent)) return null
			continue
		}

		for (const anchor of anchors) {
			if (await isIssuedBy(current, anchor)) return [...chain, anchor]
		}
	}
	return null
}

// Verifies everything except the time. The caller compares the window with the current time,
// so a cached verdict follows the validity period of the certificates.
async function evaluate(state: TrustPolicyState, chain: readonly Uint8Array[], leafHash: string): Promise<TrustWindow | CredentialFailure> {
	if (state.allowedHashes.has(leafHash)) {
		const leaf = parseCertificate(chain[0])
		return leaf && meetsKeyRequirements(leaf) ? ALWAYS : C2paStatusCode.SIGNING_CREDENTIAL_INVALID
	}

	const parsed: ParsedCertificate[] = []
	for (const der of chain) {
		const cert = parseCertificate(der)
		if (!cert) return C2paStatusCode.SIGNING_CREDENTIAL_INVALID
		parsed.push(cert)
	}

	const leaf = parsed[0]
	if (!meetsSignerProfile(leaf) || !leaf.ekuOids.some(oid => state.ekuOids.has(oid))) return C2paStatusCode.SIGNING_CREDENTIAL_INVALID

	const path = await buildAnchorPath(parsed, state.anchors)
	if (!path || !meetsPathConstraints(path)) return C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED

	return {
		notBefore: Math.max(...path.map(cert => cert.notBefore.getTime())),
		notAfter: Math.min(...path.map(cert => cert.notAfter.getTime())),
	}
}

/**
 * Evaluates a certificate chain against a trust policy.
 *
 * The leaf is trusted when its hash is on the allowed list, or when the chain verifies up
 * to a trust anchor, the leaf meets the certificate profile of C2PA 2.4 §14.5.1.1 and carries
 * an accepted EKU, and every certificate on the path is within its validity period.
 * The policy caches the verification of each chain. The validity period is compared with the
 * current time at every call.
 *
 * @param policy - Policy created by `createTrustPolicy`
 * @param chain - DER certificates from the COSE `x5chain`, leaf first
 * @returns `null` when the policy trusts the signer, otherwise the failure code of §15.7.
 * A policy with load errors trusts no signer.
 *
 * @internal
 */
export async function evaluateCertificateTrust(policy: TrustPolicy, chain: readonly Uint8Array[]): Promise<CredentialFailure | null> {
	const state = POLICY_STATES.get(policy)
	if (!state || policy.loadErrors.length > 0 || chain.length === 0) return C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED

	const hashes = await Promise.all(chain.map(hashCertificate))
	const key = hashes.join(':')
	let pending = state.cache.get(key)
	if (!pending) {
		pending = evaluate(state, chain, hashes[0]).catch(() => C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED)
		if (state.cache.size >= MAX_CACHED_CHAINS) state.cache.delete(state.cache.keys().next().value as string)
		state.cache.set(key, pending)
	}
	const verdict = await pending
	if (typeof verdict === 'string') return verdict
	const now = Date.now()
	return verdict.notBefore <= now && now <= verdict.notAfter ? null : C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED
}

/**
 * Trust verdict for the signer of a manifest, from the result of its integrity checks.
 *
 * As in §15.7, the credential and its chain are checked whether or not the claim signature
 * verifies, so both failures can be reported. A signer is trusted only when the claim
 * signature also verifies. A manifest without a certificate adds no trust code, because its
 * claim signature already fails.
 *
 * @param policy - Policy created by `createTrustPolicy`
 * @param integrity - Integrity result of the manifest, or `null` when the segment has no manifest
 * @returns `isTrusted`, and the failure code to add to `errorCodes`, if any
 *
 * @internal
 */
export async function evaluateSignerTrust(
	policy: TrustPolicy,
	integrity: Pick<ManifestIntegrity, 'chain' | 'isSignatureValid'> | null,
): Promise<{ readonly isTrusted: boolean; readonly failure: CredentialFailure | null }> {
	if (!integrity || integrity.chain.length === 0) return { isTrusted: false, failure: null }
	const failure = await evaluateCertificateTrust(policy, integrity.chain)
	return { isTrusted: integrity.isSignatureValid && failure === null, failure }
}
