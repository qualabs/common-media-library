/**
 * Converts a Uint8Array to a Uint16Array by aligning its buffer.
 *
 * @param input - The Uint8Array to convert
 * @returns A properly aligned Uint16Array
 *
 * @group Utils
 * @beta
 */
export function convertUint8ToUint16(input: Uint8Array): Uint16Array {
	if (input.length % 2 !== 0) {
		const padded = new Uint8Array(input.length + 1);
		padded.set(input);
		return new Uint16Array(padded.buffer);
	}
	return new Uint16Array(input.buffer);
}
