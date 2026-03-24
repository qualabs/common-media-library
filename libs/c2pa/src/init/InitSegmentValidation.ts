import type { C2paManifest } from '../C2paManifest.ts'
import type { CoseKeyJwk } from '../cose/CoseKeyJwk.ts'

/**
 * A session key extracted and verified from a C2PA `c2pa.session-keys` assertion.
 *
 * Only keys whose signer binding is valid and whose validity period has not expired
 * are included in {@link InitSegmentValidation.sessionKeys}.
 *
 * @public
 */
export type ValidatedSessionKey = {
  readonly kid: string
  readonly jwk: CoseKeyJwk
  readonly minSequenceNumber: number
  readonly validityPeriod: number
  readonly createdAt: string
}

/**
 * Result of validating a C2PA init segment.
 *
 * Returned by {@link validateC2paInitSegment}.
 *
 * @public
 */
export type InitSegmentValidation = {
  /** The parsed active C2PA manifest */
  readonly activeManifest: C2paManifest
  /** DER-encoded leaf certificate from the manifest signature, or null if not found */
  readonly certificate: Uint8Array | null
  /** The manifest label used as the stream's manifest ID */
  readonly manifestId: string | null
  /** Whether the `c2pa.hash.bmff.v3` hard binding passes. True if no assertion is present. */
  readonly bmffHashValid: boolean
  /** Session keys that passed signer binding verification and are within their validity period */
  readonly sessionKeys: readonly ValidatedSessionKey[]
}
