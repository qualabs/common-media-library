import type { Fields } from '../boxes/Fields.js';
import type { VisualSampleEntryBox } from '../boxes/VisualSampleEntryBox.js';
import type { IsoView } from '../IsoView.js';
import { avc1 } from './avc1.js';

/**
 * Parse a VisualSampleEntryBox from an IsoView
 *
 * @param view - The IsoView to read data from
 *
 * @returns A parsed VisualSampleEntryBox
 *
 * @group ISOBMFF
 *
 * @beta
 */
export function hev1(view: IsoView): Fields<VisualSampleEntryBox<'hev1'>> {
	return avc1(view);
}
