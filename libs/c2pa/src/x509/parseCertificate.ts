import {
	ASN1_TAG_BIT_STRING,
	ASN1_TAG_BOOLEAN,
	ASN1_TAG_CONTEXT_0,
	ASN1_TAG_CONTEXT_3,
	ASN1_TAG_GENERALIZED_TIME,
	ASN1_TAG_INTEGER,
	ASN1_TAG_OBJECT_IDENTIFIER,
	ASN1_TAG_OCTET_STRING,
	ASN1_TAG_SEQUENCE,
	ASN1_TAG_UTC_TIME,
	decodeOid,
	readElement,
	readUnsigned,
	type Asn1Element,
} from './asn1.ts'
import { CURVE_P256, CURVE_P384, CURVE_P521 } from '../cose/constants.ts'

const OID_BASIC_CONSTRAINTS = '2.5.29.19'
const OID_KEY_USAGE = '2.5.29.15'
const OID_EXTENDED_KEY_USAGE = '2.5.29.37'
const OID_AUTHORITY_KEY_IDENTIFIER = '2.5.29.35'
/** @internal */
export const OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1'
/** @internal */
export const OID_RSASSA_PSS = '1.2.840.113549.1.1.10'

// The named curves that C2PA 2.4 §14.5.1.1 allows, by OID, as WebCrypto names.
const NAMED_CURVES: Readonly<Record<string, string>> = {
	'1.2.840.10045.3.1.7': CURVE_P256,
	'1.3.132.0.34': CURVE_P384,
	'1.3.132.0.35': CURVE_P521,
}
const KEY_USAGE_DIGITAL_SIGNATURE_MASK = 0x80
const KEY_USAGE_KEY_CERT_SIGN_MASK = 0x04
const ISSUER_UNIQUE_ID_TAG = 0x81
const SUBJECT_UNIQUE_ID_TAG = 0x82

// Extensions that a critical flag does not make unacceptable. The same set as c2pa-rs.
const KNOWN_EXTENSIONS: ReadonlySet<string> = /* @__PURE__ */ new Set([
	OID_BASIC_CONSTRAINTS,
	OID_KEY_USAGE,
	OID_EXTENDED_KEY_USAGE,
	OID_AUTHORITY_KEY_IDENTIFIER,
	'2.5.29.14', // subjectKeyIdentifier
	'2.5.29.17', // subjectAltName
	'2.5.29.20', // cRLNumber
	'2.5.29.21', // reasonCode
	'2.5.29.24', // invalidityDate
	'2.5.29.30', // nameConstraints
	'2.5.29.31', // cRLDistributionPoints
	'2.5.29.32', // certificatePolicies
	'2.5.29.33', // policyMappings
	'2.5.29.36', // policyConstraints
	'2.5.29.54', // inhibitAnyPolicy
	'1.3.6.1.5.5.7.1.1', // authorityInfoAccess
	'2.16.840.1.113730.1.1', // netscapeCertType
])

const UTC_TIME_PATTERN = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/
const GENERALIZED_TIME_PATTERN = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/

const TEXT_DECODER = /* @__PURE__ */ new TextDecoder()

/**
 * Fields of an X.509 certificate needed for certificate path validation.
 *
 * @internal
 */
export type ParsedCertificate = {
	readonly der: Uint8Array
	readonly tbsCertificate: Uint8Array
	readonly signatureAlgorithm: string
	readonly signatureAlgorithmParams: Uint8Array | null
	readonly signatureValue: Uint8Array
	readonly issuer: Uint8Array
	readonly subject: Uint8Array
	readonly notBefore: Date
	readonly notAfter: Date
	readonly spki: Uint8Array
	readonly version: number
	readonly hasUniqueIds: boolean
	/** OID of the subject public key algorithm */
	readonly keyAlgorithm: string
	/** WebCrypto name of the curve of an EC key on P-256, P-384, or P-521, otherwise `null` */
	readonly keyCurve: string | null
	/** Modulus length of an RSA or RSASSA-PSS key, otherwise `null` */
	readonly rsaModulusBits: number | null
	readonly ekuOids: readonly string[]
	readonly isCa: boolean
	/** `pathLenConstraint` of the basic constraints, or `null` when absent */
	readonly pathLength: number | null
	readonly digitalSignature: boolean
	readonly keyCertSign: boolean
	readonly hasAuthorityKeyId: boolean
	readonly hasUnknownCriticalExtension: boolean
}

type Extensions = Pick<ParsedCertificate,
	'ekuOids' | 'isCa' | 'pathLength' | 'digitalSignature' | 'keyCertSign' | 'hasAuthorityKeyId' | 'hasUnknownCriticalExtension'>

type PublicKeyInfo = Pick<ParsedCertificate, 'keyAlgorithm' | 'keyCurve' | 'rsaModulusBits'>

const NO_EXTENSIONS: Extensions = {
	ekuOids: [],
	isCa: false,
	pathLength: null,
	digitalSignature: false,
	keyCertSign: false,
	hasAuthorityKeyId: false,
	hasUnknownCriticalExtension: false,
}

function parseTime(element: Asn1Element): Date | null {
	const text = TEXT_DECODER.decode(element.value)
	let match: RegExpExecArray | null
	let year: number
	if (element.tag === ASN1_TAG_UTC_TIME && (match = UTC_TIME_PATTERN.exec(text))) {
		const yy = Number(match[1])
		year = yy >= 50 ? 1900 + yy : 2000 + yy
	}
	else if (element.tag === ASN1_TAG_GENERALIZED_TIME && (match = GENERALIZED_TIME_PATTERN.exec(text))) {
		year = Number(match[1])
	}
	else {
		return null
	}
	return new Date(Date.UTC(year, Number(match[2]) - 1, Number(match[3]), Number(match[4]), Number(match[5]), Number(match[6])))
}

type Asn1Child = Asn1Element & { readonly raw: Uint8Array }

function readChildren(value: Uint8Array): Asn1Child[] {
	const children: Asn1Child[] = []
	let offset = 0
	while (offset < value.length) {
		const el = readElement(value, offset)
		if (!el) throw new Error('Malformed ASN.1')
		children.push({ ...el, raw: value.subarray(offset, offset + el.totalSize) })
		offset += el.totalSize
	}
	return children
}

function parseExtensions(wrapper: Uint8Array): Extensions {
	const result: { -readonly [K in keyof Extensions]: Extensions[K] } = { ...NO_EXTENSIONS }
	const list = readElement(wrapper, 0)
	if (!list || list.tag !== ASN1_TAG_SEQUENCE) throw new Error('Malformed extensions')

	for (const ext of readChildren(list.value)) {
		const fields = readChildren(ext.value)
		const oidEl = fields[0]
		const valueEl = fields[fields.length - 1]
		if (oidEl?.tag !== ASN1_TAG_OBJECT_IDENTIFIER || valueEl?.tag !== ASN1_TAG_OCTET_STRING) continue
		const inner = readElement(valueEl.value, 0)
		if (!inner) throw new Error('Malformed extension value')

		const oid = decodeOid(oidEl.value)
		const critical = fields.length === 3 && fields[1].tag === ASN1_TAG_BOOLEAN && fields[1].value[0] !== 0
		if (critical && !KNOWN_EXTENSIONS.has(oid)) result.hasUnknownCriticalExtension = true

		switch (oid) {
			case OID_BASIC_CONSTRAINTS: {
				const constraints = readChildren(inner.value)
				result.isCa = constraints[0]?.tag === ASN1_TAG_BOOLEAN && constraints[0].value[0] !== 0
				const pathLength = constraints.find(el => el.tag === ASN1_TAG_INTEGER)
				result.pathLength = pathLength ? readUnsigned(pathLength.value) : null
				break
			}
			case OID_KEY_USAGE:
				if (inner.tag === ASN1_TAG_BIT_STRING) {
					const usage = inner.value[1] ?? 0
					result.digitalSignature = (usage & KEY_USAGE_DIGITAL_SIGNATURE_MASK) !== 0
					result.keyCertSign = (usage & KEY_USAGE_KEY_CERT_SIGN_MASK) !== 0
				}
				break
			case OID_AUTHORITY_KEY_IDENTIFIER:
				result.hasAuthorityKeyId = true
				break
			case OID_EXTENDED_KEY_USAGE:
				result.ekuOids = readChildren(inner.value)
					.filter(el => el.tag === ASN1_TAG_OBJECT_IDENTIFIER)
					.map(el => decodeOid(el.value))
				break
		}
	}
	return result
}

function countBits(value: Uint8Array): number {
	let start = 0
	while (start < value.length && value[start] === 0) start++
	if (start === value.length) return 0
	return (value.length - start - 1) * 8 + (32 - Math.clz32(value[start]))
}

function parsePublicKeyInfo(spki: Uint8Array): PublicKeyInfo {
	const [algId, key] = readChildren(spki)
	const [algOid, params] = algId?.tag === ASN1_TAG_SEQUENCE ? readChildren(algId.value) : []
	if (algOid?.tag !== ASN1_TAG_OBJECT_IDENTIFIER) throw new Error('Malformed public key algorithm')
	const keyAlgorithm = decodeOid(algOid.value)

	const keyCurve = keyAlgorithm === OID_EC_PUBLIC_KEY && params?.tag === ASN1_TAG_OBJECT_IDENTIFIER ? NAMED_CURVES[decodeOid(params.value)] ?? null : null

	let rsaModulusBits: number | null = null
	if ((keyAlgorithm === OID_RSA_ENCRYPTION || keyAlgorithm === OID_RSASSA_PSS) && key?.tag === ASN1_TAG_BIT_STRING) {
		const rsaKey = readElement(key.value, 1)
		const modulus = rsaKey?.tag === ASN1_TAG_SEQUENCE ? readElement(rsaKey.value, 0) : null
		if (modulus?.tag === ASN1_TAG_INTEGER) rsaModulusBits = countBits(modulus.value)
	}
	return { keyAlgorithm, keyCurve, rsaModulusBits }
}

/**
 * Parses a DER-encoded X.509 certificate into the fields used for path validation.
 *
 * @param certDER - DER-encoded X.509 certificate bytes
 * @returns The parsed certificate, or `null` if parsing fails
 *
 * @internal
 */
export function parseCertificate(certDER: Uint8Array): ParsedCertificate | null {
	try {
		const cert = readElement(certDER, 0)
		if (!cert || cert.tag !== ASN1_TAG_SEQUENCE) return null
		const [tbs, sigAlg, sigValue] = readChildren(cert.value)
		if (tbs?.tag !== ASN1_TAG_SEQUENCE || sigAlg?.tag !== ASN1_TAG_SEQUENCE || sigValue?.tag !== ASN1_TAG_BIT_STRING) return null

		const [algOid, algParams] = readChildren(sigAlg.value)
		if (algOid?.tag !== ASN1_TAG_OBJECT_IDENTIFIER) return null

		const tbsFields = readChildren(tbs.value)
		const start = tbsFields[0]?.tag === ASN1_TAG_CONTEXT_0 ? 1 : 0
		const versionEl = start ? readElement(tbsFields[0].value, 0) : null
		const version = versionEl?.tag === ASN1_TAG_INTEGER ? readUnsigned(versionEl.value) + 1 : 1
		const [serial, , issuer, validity, subject, spki, ...optional] = tbsFields.slice(start)
		if (serial?.tag !== ASN1_TAG_INTEGER || issuer?.tag !== ASN1_TAG_SEQUENCE || validity?.tag !== ASN1_TAG_SEQUENCE ||
			subject?.tag !== ASN1_TAG_SEQUENCE || spki?.tag !== ASN1_TAG_SEQUENCE) {
			return null
		}

		const [notBeforeEl, notAfterEl] = readChildren(validity.value)
		const notBefore = notBeforeEl ? parseTime(notBeforeEl) : null
		const notAfter = notAfterEl ? parseTime(notAfterEl) : null
		if (!notBefore || !notAfter) return null

		const extensionsEl = optional.find(el => el.tag === ASN1_TAG_CONTEXT_3)
		const extensions = extensionsEl ? parseExtensions(extensionsEl.value) : NO_EXTENSIONS

		return {
			der: certDER,
			tbsCertificate: tbs.raw,
			signatureAlgorithm: decodeOid(algOid.value),
			signatureAlgorithmParams: algParams?.raw ?? null,
			signatureValue: sigValue.value.subarray(1),
			issuer: issuer.raw,
			subject: subject.raw,
			notBefore,
			notAfter,
			spki: spki.raw,
			version,
			hasUniqueIds: optional.some(el => el.tag === ISSUER_UNIQUE_ID_TAG || el.tag === SUBJECT_UNIQUE_ID_TAG),
			...parsePublicKeyInfo(spki.value),
			...extensions,
		}
	}
	catch {
		return null
	}
}

