/**
 * Trust sources for {@link createTrustPolicy}.
 *
 * Each field is one string. A string that contains `-----BEGIN` or a line break is inline content.
 * A string that starts with `http://` or `https://` is fetched. Any other string is a local file path,
 * which requires Node.
 *
 * @public
 */
export type TrustPolicyOptions = {
	/** PEM certificates of trusted certificate authorities */
	readonly trustAnchors?: string
	/** PEM certificates or base64 SHA-256 hashes of trusted signing certificates */
	readonly allowedList?: string
	/** Accepted Extended Key Usage OIDs, one per line. Replaces the default set of C2PA 2.4 §14.4.1. */
	readonly trustConfig?: string
}

/**
 * A loaded, immutable trust policy. Create it with {@link createTrustPolicy} and pass it
 * to the validation functions in their options.
 *
 * @public
 */
export type TrustPolicy = {
	/**
	 * One message per trust source that failed to load or had no usable entries.
	 * When this list is not empty, the policy trusts no certificate.
	 */
	readonly loadErrors: readonly string[]
}
