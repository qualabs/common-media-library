import type { IsoView } from '../IsoView';

/**
 * ISO/IEC 14496-12:2012 - 8.1.2 Free Space Box
 *
 * @group ISOBMFF
 *
 * @beta
 */
export type FreeSpaceBox = {
	data: Uint8Array;
};

/**
 * Parse a Box from an IsoView
 *
 * @param view - The IsoView to read data from
 *
 * @returns A parsed Box
 *
 * @group ISOBMFF
 *
 * @beta
 */
export function free(view: IsoView): FreeSpaceBox {
	return {
		data: view.readData(-1),
	};
};
