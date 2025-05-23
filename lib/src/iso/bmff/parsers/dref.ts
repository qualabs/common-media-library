import type { Box } from '../Box';
import type { FullBox } from '../FullBox';
import type { IsoView } from '../IsoView';

/**
 * ISO/IEC 14496-12:2012 - 8.7.2 Data Reference Box
 *
 * @group ISOBMFF
 *
 * @beta
 */
export type DataReferenceBox = FullBox & {
	entryCount: number;
	entries: Box[];
};

/**
 * Parse a DataReferenceBox from an IsoView
 *
 * @param view - The IsoView to read data from
 *
 * @returns A parsed DataReferenceBox
 *
 * @group ISOBMFF
 *
 * @beta
 */
export function dref(view: IsoView): DataReferenceBox {
	const { version, flags } = view.readFullBox();
	const entryCount = view.readUint(4);
	const entries = view.readBoxes(entryCount);

	return {
		version,
		flags,
		entryCount,
		entries,
	};
};
