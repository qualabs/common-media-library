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
import { ASN1_TAG_INTEGER, ASN1_TAG_OBJECT_IDENTIFIER, ASN1_TAG_SEQUENCE, decodeOid, readElement, readUnsigned } from './asn1.ts'
import { normalizeRsaPssSpki } from './normalizeRsaPssSpki.ts'
import { OID_RSASSA_PSS, type ParsedCertificate } from './parseCertificate.ts'

const RSASSA_PKCS1_V1_5_ALGORITHM = 'RSASSA-PKCS1-v1_5'
const PSS_HASH_TAG = 0xa0
const PSS_SALT_LENGTH_TAG = 0xa2
const PSS_DEFAULT_SALT_LENGTH = 20

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

const CURVE_COMPONENT_BYTES: Readonly<Record<string, number>> = { [CURVE_P256]: 32, [CURVE_P384]: 48, [CURVE_P521]: 66 }

const OID_ED25519 = '1.3.101.112'

type VerifyParams = {
	readonly importAlgorithm: AlgorithmIdentifier | EcKeyImportParams | RsaHashedImportParams
	readonly verifyAlgorithm: AlgorithmIdentifier | EcdsaParams | RsaPssParams
	readonly spki: Uint8Array
	readonly signature: Uint8Array
}

function readPssParams(params: Uint8Array | null): { hash: string; saltLength: number } | null {
	const seq = params && readElement(params, 0)
	if (seq?.tag !== ASN1_TAG_SEQUENCE) return null
	let hash: string | null = null
	let saltLength = PSS_DEFAULT_SALT_LENGTH
	let offset = 0
	while (offset < seq.value.length) {
		const field = readElement(seq.value, offset)
		if (!field) return null
		const inner = readElement(field.value, 0)
		if (field.tag === PSS_HASH_TAG && inner?.tag === ASN1_TAG_SEQUENCE) {
			const oid = readElement(inner.value, 0)
			if (oid?.tag === ASN1_TAG_OBJECT_IDENTIFIER) hash = DIGEST_HASHES[decodeOid(oid.value)] ?? null
		}
		if (field.tag === PSS_SALT_LENGTH_TAG && inner?.tag === ASN1_TAG_INTEGER) {
			saltLength = readUnsigned(inner.value)
		}
		offset += field.totalSize
	}
	return hash ? { hash, saltLength } : null
}

function resolveVerifyParams(child: ParsedCertificate, parent: ParsedCertificate): VerifyParams | null {
	const parentSpki = parent.spki
	const alg = child.signatureAlgorithm
	const signature = child.signatureValue

	const ecdsaHash = ECDSA_HASHES[alg]
	if (ecdsaHash) {
		const namedCurve = parent.keyCurve
		if (!namedCurve) return null
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
		if (!pss) return null
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

	return null
}

/**
 * Verifies the signature of a certificate with the public key of its issuer.
 *
 * Supports the certificate signature algorithms of C2PA 2.4 §14.5.1.1: ECDSA,
 * RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-256/384/512, and Ed25519.
 *
 * @param child - The certificate whose signature is verified
 * @param parent - The issuing certificate
 * @returns `true` if the signature is valid, `false` otherwise or when the algorithm is unsupported
 *
 * @internal
 */
export async function verifyCertificateSignature(child: ParsedCertificate, parent: ParsedCertificate): Promise<boolean> {
	try {
		const params = resolveVerifyParams(child, parent)
		if (!params) return false
		const key = await crypto.subtle.importKey('spki', params.spki as Uint8Array<ArrayBuffer>, params.importAlgorithm, false, ['verify'])
		return await crypto.subtle.verify(params.verifyAlgorithm, key, params.signature as Uint8Array<ArrayBuffer>, child.tbsCertificate as Uint8Array<ArrayBuffer>)
	}
	catch {
		return false
	}
}
