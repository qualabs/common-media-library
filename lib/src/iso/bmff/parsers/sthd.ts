import type { FullBox } from '../FullBox.js';
import type { IsoView } from '../IsoView.js';

/**
 * ISO/IEC 14496-12:2015 - 12.6.2 Subtitle media header Box
 *
 * @group ISOBMFF
 *
 * @beta
 */
export type SubtitleMediaHeaderBox = FullBox;

/**
 * Parse a SubtitleMediaHeaderBox from an IsoView
 *
 * @param view - The IsoView to read data from
 *
 * @returns A parsed SubtitleMediaHeaderBox
 *
 * @group ISOBMFF
 *
 * @beta
 */
export function sthd(view: IsoView): SubtitleMediaHeaderBox {
	return view.readFullBox();
};
