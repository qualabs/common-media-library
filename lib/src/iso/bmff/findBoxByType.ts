import type { Box } from './Box.js';
import { findBox } from './findBox.js';
import type { IsoData } from './IsoData.js';
import type { IsoViewConfig } from './IsoViewConfig.js';

/**
 * Find a box from an IsoView that matches a given type
 *
 * @param type - The type of box to find
 * @param raw - The raw ISO data
 * @param config - The configuration for the IsoView
 *
 * @returns The first box that matches the type
 *
 * @group ISOBMFF
 *
 * @beta
 */
export function findBoxByType(type: string, raw: IsoData, config: IsoViewConfig = {}): Box | null {
	return findBox(raw, config, box => box.type === type);
}
