import type { ManifestIntegrity } from '../claim/validateManifestIntegrity.ts'
import type { TrustFailure, TrustPolicy } from './TrustPolicy.ts'

/**
 * Trust verdict for the signer of a manifest, from the result of its integrity checks.
 *
 * As in §15.7, the credential and its chain are checked whether or not the claim signature
 * verifies, so both failures can be reported. A signer is trusted only when the claim
 * signature also verifies. A manifest without a certificate adds no trust code, because its
 * claim signature already fails.
 *
 * @param policy - The trust policy from the validation options
 * @param integrity - Integrity result of the manifest, or `null` when the segment has no manifest
 * @returns `isTrusted`, and the failure code to add to `errorCodes`, if any
 *
 * @internal
 */
export async function evaluateSignerTrust(
	policy: TrustPolicy,
	integrity: Pick<ManifestIntegrity, 'chain' | 'isSignatureValid'> | null,
): Promise<{ readonly isTrusted: boolean; readonly failure: TrustFailure | null }> {
	if (!integrity || integrity.chain.length === 0) return { isTrusted: false, failure: null }
	const failure = await policy.evaluate(integrity.chain)
	return { isTrusted: integrity.isSignatureValid && failure === null, failure }
}
