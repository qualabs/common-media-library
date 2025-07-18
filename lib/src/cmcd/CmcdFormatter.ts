import type { SfItem } from '../structuredfield/SfItem.js';
import type { ValueOrArray } from '../utils/ValueOrArray.js';
import type { CmcdEncodeOptions } from './CmcdEncodeOptions.js';
import type { CmcdValue } from './CmcdValue.js';

/**
 * A formatter for CMCD values.
 *
 * @param value - The value to format.
 *
 * @returns The formatted value.
 *
 * @group CMCD
 *
 * @beta
 */
export type CmcdFormatter = (value: CmcdValue, options?: CmcdEncodeOptions) => number | ValueOrArray<string> | ValueOrArray<SfItem>;
