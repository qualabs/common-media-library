import { dataViewToString } from '../../../utils/dataViewToString.js';

export function readUtf8String(dataView: DataView, offset: number): string {
	const length = dataView.byteLength - (offset - dataView.byteOffset);
	return (length > 0) ? dataViewToString(new DataView(dataView.buffer, offset, length)) : '';
};
