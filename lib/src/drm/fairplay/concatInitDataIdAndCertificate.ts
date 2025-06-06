import { stringToUint16 } from '../../utils/stringToUint16.js';

/**
 * Concatenates InitData, ID, and Certificate for FairPlay DRM.
 *
 * @param initData - The initialization data (PSSH box)
 * @param id - The content ID (string or Uint16Array)
 * @param cert - The application certificate (Uint8Array)
 * @returns A Uint8Array containing the concatenated data
 *
 * @group DRM
 * @beta
 *
 * @example
 * {@includeCode ../../../test/drm/fairplay/concatInitDataIdAndCertificate.test.ts#example}
 */

export function concatInitDataIdAndCertificate(initData: Uint16Array, id: Uint16Array | string, cert: Uint8Array): Uint8Array {
	if (typeof id === 'string') {
		id = stringToUint16(id);
	}
	const buffer = new ArrayBuffer(initData.byteLength + 4 + id.byteLength + 4 + cert.byteLength);
	const dataView = new DataView(buffer);
	let offset = 0;

	new Uint8Array(buffer, offset, initData.byteLength).set(initData);
	offset += initData.byteLength;

	dataView.setUint32(offset, id.byteLength, true);
	offset += 4;
	new Uint16Array(buffer, offset, id.length).set(id);
	offset += id.byteLength;

	dataView.setUint32(offset, cert.byteLength, true);
	offset += 4;
	new Uint8Array(buffer, offset, cert.byteLength).set(cert);

	return new Uint8Array(buffer);
}
