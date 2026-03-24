const MILLISECONDS_PER_SECOND = 1000

/**
 * Converts a Uint8Array to a lowercase hex string.
 *
 * @internal
 */
export function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes)
		.map(b => b.toString(16).padStart(2, '0'))
		.join('')
}

/**
 * Checks whether a session key has expired based on its creation time
 * and validity period.
 *
 * @param createdAt - ISO 8601 date string when the key was created
 * @param validityPeriodSeconds - Validity duration in seconds
 * @param now - Current time (defaults to `new Date()`, injectable for testing)
 * @returns `true` if the key has expired
 *
 * @internal
 */
export function isKeyExpired(createdAt: string, validityPeriodSeconds: number, now: Date = new Date()): boolean {
	const validityEnd = new Date(new Date(createdAt).getTime() + validityPeriodSeconds * MILLISECONDS_PER_SECOND)
	return now > validityEnd
}

const FULLBOX_HEADER_SIZE = 4
const AUX_UUID_OFFSET_SIZE = 8

/**
 * Strips the JUMBF UUID box prefix (fullbox header, purpose string, aux offset)
 * to return only the JUMBF manifest data.
 *
 * Structure per ISO 19566-5 / C2PA BMFF storage:
 *   version(1) + flags(3) + purpose(null-terminated) + aux_offset(8) + JUMBF data
 *
 * @internal
 */
export function stripJumbfUuidPrefix(payload: Uint8Array): Uint8Array {
	let offset = FULLBOX_HEADER_SIZE
	// Skip null-terminated purpose string (e.g. "manifest\0")
	while (offset < payload.length && payload[offset] !== 0) offset++
	offset++ // skip the null terminator
	offset += AUX_UUID_OFFSET_SIZE
	return payload.subarray(offset)
}
