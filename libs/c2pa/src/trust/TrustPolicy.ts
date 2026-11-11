import type { C2paStatusCode } from '../C2paStatusCode.ts'

/**
 * Trust sources and settings for {@link createTrustPolicy}.
 *
 * Each source is text content. To use a file or a URL, load its text first.
 *
 * @public
 */
export type TrustPolicyOptions = {
	/** PEM certificates of trusted certificate authorities */
	readonly trustAnchors?: string
	/** PEM certificates or base64 SHA-256 hashes of trusted signing certificates, one hash per line */
	readonly allowedList?: string
	/** Extended Key Usage OIDs to accept in addition to the default set of C2PA 2.4 §14.4.1, one per line */
	readonly trustConfig?: string
	/** Returns the time to compare with validity periods. Defaults to the current time. */
	readonly validationTime?: () => Date
	/** Milliseconds of clock difference to accept at each end of a validity period. Defaults to 0. */
	readonly clockTolerance?: number
}

/**
 * Why a trust policy rejects a signing credential.
 *
 * @public
 */
export type TrustFailure =
	| typeof C2paStatusCode.SIGNING_CREDENTIAL_INVALID
	| typeof C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED
	| typeof C2paStatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY
	| typeof C2paStatusCode.ALGORITHM_UNSUPPORTED

/**
 * Decides whether the signer of a manifest is trusted. Create it with {@link createTrustPolicy}
 * and pass it to the validation functions in their options.
 *
 * @public
 */
export type TrustPolicy = {
	/**
	 * Evaluates the `x5chain` of a claim signature.
	 *
	 * @param chain - DER certificates, leaf first
	 * @returns `null` when the policy trusts the signer, otherwise the failure code
	 */
	readonly evaluate: (chain: readonly Uint8Array[]) => Promise<TrustFailure | null>
}
