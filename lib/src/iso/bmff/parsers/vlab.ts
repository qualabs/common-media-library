import type { IsoView } from '../IsoView';

/**
 * ISO/IEC 14496-30:2014 - WebVTT Source Label Box
 *
 * @group ISOBMFF
 *
 * @beta
 */
export type WebVTTSourceLabelBox = {
	sourceLabel: string;
};

/**
 * Parse a WebVTTSourceLabelBox from an IsoView
 *
 * @param view - The IsoView to read data from
 *
 * @returns A parsed WebVTTSourceLabelBox
 *
 * @group ISOBMFF
 *
 * @beta
 */
export function vlab(view: IsoView): WebVTTSourceLabelBox {
	return {
		sourceLabel: view.readUtf8(-1),
	};
};
