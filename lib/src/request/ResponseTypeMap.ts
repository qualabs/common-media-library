import type { XmlNode } from '../xml/XmlNode.js';

/**
 * The a request's `responseType` to the corresponding data type.
 *
 * @group Request
 *
 * @beta
 */
export type ResponseTypeMap<T extends string | undefined> =
	T extends 'json' ? any :
		T extends 'text' ? string :
			T extends 'blob' ? Blob :
				T extends 'arraybuffer' ? ArrayBuffer :
					T extends 'document' ? XmlNode :
						unknown;
