import type { FullBox } from '../FullBox.js';
import type { IsoView } from '../IsoView.js';

/**
 * ISO/IEC 14496-12:202x - 8.10.4 Track kind box
 *
 * @group ISOBMFF
 *
 * @beta
 */
export type TrackKindBox = FullBox & {
	schemeUri: string;
	value: string;
};

/**
 * Parse a TrackKinBox from an IsoView
 *
 * @param view - The IsoView to read data from
 *
 * @returns A parsed TrackKindBox
 *
 * @group ISOBMFF
 *
 * @beta
 */
export function kind(view: IsoView): TrackKindBox {
	return {
		...view.readFullBox(),
		schemeUri: view.readUtf8(-1),
		value: view.readUtf8(-1),
	};
};
