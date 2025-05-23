import type { SfBareItem } from '../SfBareItem';
import { SfItem } from '../SfItem.ts';
import { serializeBareItem } from './serializeBareItem.ts';
import { serializeParams } from './serializeParams.ts';

// 4.1.3.  Serializing an Item
//
// Given an Item as bare_item and Parameters as item_parameters, return
// an ASCII string suitable for use in a HTTP field value.
//
// 1.  Let output be an empty string.
//
// 2.  Append the result of running Serializing a Bare Item
//     Section 4.1.3.1 with bare_item to output.
//
// 3.  Append the result of running Serializing Parameters
//     Section 4.1.1.2 with item_parameters to output.
//
// 4.  Return output.
export function serializeItem(value: SfItem | SfBareItem): string {
	if (value instanceof SfItem) {
		return `${serializeBareItem(value.value)}${serializeParams(value.params)}`;
	}
	else {
		return serializeBareItem(value);
	}
}
