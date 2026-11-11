import {
	CURVE_P256,
	CURVE_P384,
	CURVE_P521,
	ECDSA_ALGORITHM,
	ED25519_ALGORITHM,
	HASH_SHA256,
	HASH_SHA384,
	HASH_SHA512,
	RSA_PSS_ALGORITHM,
} from '../cose/constants.ts'
import { derToRawEcdsaSignature } from '../cose/verifyCoseSign1.ts'
import {
	ASN1_TAG_INTEGER,
	ASN1_TAG_OBJECT_IDENTIFIER,
	ASN1_TAG_SEQUENCE,
	decodeOid,
	readElement,
	readUnsigned,
} from './asn1.ts'
import { normalizeRsaPssSpki } from './normalizeRsaPssSpki.ts'
import {
	ML_DSA_OIDS,
	OID_EC_PUBLIC_KEY,
	OID_ED25519,
	OID_RSASSA_PSS,
	type ParsedCertificate,
} from './parseCertificate.ts'

const RSASSA_PKCS1_V1_5_ALGORITHM = 'RSASSA-PKCS1-v1_5'
const PSS_HASH_TAG = 0xa0
const PSS_MASK_GEN_TAG = 0xa1
const PSS_SALT_LENGTH_TAG = 0xa2
const PSS_DEFAULT_SALT_LENGTH = 20
const OID_MGF1 = '1.2.840.113549.1.1.8'
const NOT_SUPPORTED_ERROR = 'NotSupportedError'

const ECDSA_HASHES: Readonly<Record<string, string>> = {
	'1.2.840.10045.4.3.2': HASH_SHA256,
	'1.2.840.10045.4.3.3': HASH_SHA384,
	'1.2.840.10045.4.3.4': HASH_SHA512,
}

const RSA_PKCS1_HASHES: Readonly<Record<string, string>> = {
	'1.2.840.113549.1.1.11': HASH_SHA256,
	'1.2.840.113549.1.1.12': HASH_SHA384,
	'1.2.840.113549.1.1.13': HASH_SHA512,
}

const DIGEST_HASHES: Readonly<Record<string, string>> = {
	'2.16.840.1.101.3.4.2.1': HASH_SHA256,
	'2.16.840.1.101.3.4.2.2': HASH_SHA384,
	'2.16.840.1.101.3.4.2.3': HASH_SHA512,
}

const CURVE_COMPONENT_BYTES: Readonly<Record<string, number>> = {
	[CURVE_P256]: 32,
	[CURVE_P384]: 48,
	[CURVE_P521]: 66,
}

/**
 * Outcome of a certificate signature check. `disallowed` means that C2PA 2.5 §13.5.1.1 does not
 * allow the signature algorithm or its parameters. `unsupported` means that the runtime cannot
 * verify an allowed algorithm.
 *
 * @internal
 */
export type CertificateSignatureCheck = 'verified' | 'failed' | 'disallowed' | 'unsupported'

type VerifyParams = {
	readonly importAlgorithm: AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams
	readonly verifyAlgorithm: AlgorithmIdentifier | EcdsaParams | RsaPssParams
	readonly spki: Uint8Array
	readonly signature: Uint8Array
}

function readAlgorithmOid(algorithmIdentifier: Uint8Array | undefined): string | null {
	const seq = algorithmIdentifier && readElement(algorithmIdentifier, 0)
	const oid = seq?.tag === ASN1_TAG_SEQUENCE ? readElement(seq.value, 0) : null
	return oid?.tag === ASN1_TAG_OBJECT_IDENTIFIER ? decodeOid(oid.value) : null
}

// C2PA 2.5 §13.5.1.1: hashAlgorithm and maskGenAlgorithm are present and use the same hash.
function readPssParams(params: Uint8Array | null): { hash: string; saltLength: number } | null {
	const seq = params && readElement(params, 0)
	if (seq?.tag !== ASN1_TAG_SEQUENCE) return null
	let hashOid: string | null = null
	let maskGenHashOid: string | null = null
	let saltLength = PSS_DEFAULT_SALT_LENGTH
	let offset = 0
	while (offset < seq.value.length) {
		const field = readElement(seq.value, offset)
		if (!field) return null
		if (field.tag === PSS_HASH_TAG) hashOid = readAlgorithmOid(field.value)
		if (field.tag === PSS_MASK_GEN_TAG) {
			const maskGen = readElement(field.value, 0)
			if (maskGen?.tag === ASN1_TAG_SEQUENCE && readAlgorithmOid(field.value) === OID_MGF1) {
				const mgfOid = readElement(maskGen.value, 0)
				if (mgfOid) maskGenHashOid = readAlgorithmOid(maskGen.value.subarray(mgfOid.totalSize))
			}
		}
		if (field.tag === PSS_SALT_LENGTH_TAG) {
			const inner = readElement(field.value, 0)
			if (inner?.tag !== ASN1_TAG_INTEGER) return null
			saltLength = readUnsigned(inner.value)
		}
		offset += field.totalSize
	}
	const hash = hashOid ? DIGEST_HASHES[hashOid] : undefined
	return hash && hashOid === maskGenHashOid ? { hash, saltLength } : null
}

/**
 * Checks that C2PA 2.5 §13.5.1.1 allows the signature algorithm of a certificate.
 *
 * @internal
 */
export function isAllowedSignatureAlgorithm(cert: ParsedCertificate): boolean {
	const alg = cert.signatureAlgorithm
	if (alg === OID_RSASSA_PSS) return readPssParams(cert.signatureAlgorithmParams) !== null
	return (
		alg in ECDSA_HASHES || alg in RSA_PKCS1_HASHES || alg === OID_ED25519 || ML_DSA_OIDS.has(alg)
	)
}

function resolveVerifyParams(
	child: ParsedCertificate,
	parent: ParsedCertificate,
): VerifyParams | Exclude<CertificateSignatureCheck, 'verified'> {
	const parentSpki = parent.spki
	const alg = child.signatureAlgorithm
	const signature = child.signatureValue

	const ecdsaHash = ECDSA_HASHES[alg]
	if (ecdsaHash) {
		const namedCurve = parent.keyCurve
		if (parent.keyAlgorithm !== OID_EC_PUBLIC_KEY) return 'failed'
		if (!namedCurve) return 'unsupported'
		return {
			importAlgorithm: { name: ECDSA_ALGORITHM, namedCurve },
			verifyAlgorithm: { name: ECDSA_ALGORITHM, hash: ecdsaHash },
			spki: parentSpki,
			signature: derToRawEcdsaSignature(signature, CURVE_COMPONENT_BYTES[namedCurve]),
		}
	}

	const pkcs1Hash = RSA_PKCS1_HASHES[alg]
	if (pkcs1Hash) {
		return {
			importAlgorithm: { name: RSASSA_PKCS1_V1_5_ALGORITHM, hash: pkcs1Hash },
			verifyAlgorithm: { name: RSASSA_PKCS1_V1_5_ALGORITHM },
			spki: normalizeRsaPssSpki(parentSpki),
			signature,
		}
	}

	if (alg === OID_RSASSA_PSS) {
		const pss = readPssParams(child.signatureAlgorithmParams)
		if (!pss) return 'disallowed'
		return {
			importAlgorithm: { name: RSA_PSS_ALGORITHM, hash: pss.hash },
			verifyAlgorithm: { name: RSA_PSS_ALGORITHM, saltLength: pss.saltLength },
			spki: normalizeRsaPssSpki(parentSpki),
			signature,
		}
	}

	if (alg === OID_ED25519) {
		return {
			importAlgorithm: { name: ED25519_ALGORITHM },
			verifyAlgorithm: { name: ED25519_ALGORITHM },
			spki: parentSpki,
			signature,
		}
	}

	// C2PA 2.5 §13.5.1.1 allows ML-DSA. WebCrypto does not implement it.
	return ML_DSA_OIDS.has(alg) ? 'unsupported' : 'disallowed'
}

/**
 * Verifies the signature of a certificate with the public key of its issuer.
 *
 * Supports the certificate signature algorithms of C2PA 2.5 §13.5.1.1 except ML-DSA: ECDSA,
 * RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-256/384/512, and Ed25519.
 *
 * @param child - The certificate whose signature is verified
 * @param parent - The issuing certificate
 * @returns The outcome of the check
 *
 * @internal
 */
export async function verifyCertificateSignature(
	child: ParsedCertificate,
	parent: ParsedCertificate,
): Promise<CertificateSignatureCheck> {
	try {
		const params = resolveVerifyParams(child, parent)
		if (typeof params === 'string') return params
		const key = await crypto.subtle.importKey(
			'spki',
			params.spki as Uint8Array<ArrayBuffer>,
			params.importAlgorithm,
			false,
			['verify'],
		)
		const verified = await crypto.subtle.verify(
			params.verifyAlgorithm,
			key,
			params.signature as Uint8Array<ArrayBuffer>,
			child.tbsCertificate as Uint8Array<ArrayBuffer>,
		)
		return verified ? 'verified' : 'failed'
	} catch (error) {
		return error instanceof Error && error.name === NOT_SUPPORTED_ERROR ? 'unsupported' : 'failed'
	}
}
