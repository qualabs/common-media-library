import type { SfEncodeOptions } from '../SfEncodeOptions';
import { SfItem } from '../SfItem.ts';
import type { SfMember } from '../SfMember';
import { LIST } from '../utils/LIST.ts';
import { serializeError } from './serializeError.ts';
import { serializeInnerList } from './serializeInnerList.ts';
import { serializeItem } from './serializeItem.ts';

// 4.1.1.  Serializing a List
//
// Given an array of (member_value, parameters) tuples as input_list,
// return an ASCII string suitable for use in a HTTP field value.
//
// 1.  Let output be an empty string.
//
// 2.  For each (member_value, parameters) of input_list:
//
//     1.  If member_value is an array, append the result of running
//         Serializing an Inner List (Section 4.1.1.1) with
//         (member_value, parameters) to output.
//
//     2.  Otherwise, append the result of running Serializing an Item
//         (Section 4.1.3) with (member_value, parameters) to output.
//
//     3.  If more member_values remain in input_list:
//
//         1.  Append "," to output.
//
//         2.  Append a single SP to output.
//
// 3.  Return output.
export function serializeList(list: SfMember[], options: SfEncodeOptions = { whitespace: true }): string {
	if (Array.isArray(list) === false) {
		throw serializeError(list, LIST);
	}

	const optionalWhiteSpace = options?.whitespace ? ' ' : '';

	return list
		.map(item => {
			if (item instanceof SfItem === false) {
				item = new SfItem(item);
			}

			// TODO: Fix this type assertion
			const i = item as any;
			if (Array.isArray(i.value)) {
				return serializeInnerList(i);
			}

			return serializeItem(i);
		})
		.join(`,${optionalWhiteSpace}`);
}
