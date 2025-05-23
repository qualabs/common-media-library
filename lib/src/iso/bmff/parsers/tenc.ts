import { UINT } from '../fields/UINT.ts';
import type { FullBox } from '../FullBox';
import type { IsoView } from '../IsoView';

/**
 * ISO/IEC 23001-7:2011 - 8.2 Track Encryption Box
 *
 * @group ISOBMFF
 *
 * @beta
 */
export type TrackEncryptionBox = FullBox & {
	defaultIsEncrypted: number;
	defaultIvSize: number;
	defaultKid: number[];
};

/**
 * Parse a TrackEncryptionBox from an IsoView
 *
 * @param view - The IsoView to read data from
 *
 * @returns A parsed TrackEncryptionBox
 *
 * @group ISOBMFF
 *
 * @beta
 */
export function tenc(view: IsoView): TrackEncryptionBox {
	return {
		...view.readFullBox(),
		defaultIsEncrypted: view.readUint(3),
		defaultIvSize: view.readUint(1),
		defaultKid: view.readArray(UINT, 1, 16),
	};
};
