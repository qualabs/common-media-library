import { dataViewToString } from '../../../utils/dataViewToString.js';

export function readUtf8TerminatedString(dataView: DataView, offset: number): string {
	const length = dataView.byteLength - (offset - dataView.byteOffset);

	let data = '';

	if (length > 0) {
		const view = new DataView(dataView.buffer, offset, length);

		let l = 0;

		for (; l < length; l++) {
			if (view.getUint8(l) === 0) {
				break;
			}
		}

		// remap the Dataview with the actual length
		data = dataViewToString(new DataView(dataView.buffer, offset, l));
	}

	return data;
};
