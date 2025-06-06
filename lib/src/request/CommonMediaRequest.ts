import type { Cmcd } from '../cmcd/Cmcd.js';
import type { RequestType } from './RequestType.js';

/**
 * Common request API.
 *
 * @group Request
 *
 * @beta
 */
export type CommonMediaRequest = {

	/**
	 * The URL of the request.
	 */
	url: string;

	/**
	 * The request's method (GET, POST, etc).
	 */
	method?: string;

	/**
	 * The body of the request.
	 */
	body?: BodyInit;

	/**
	 * The response type with which the response from the server shall be compatible.
	 */
	responseType?: RequestType;

	/**
	 * The headers object associated with the request.
	 */
	headers?: Record<string, string>;

	/**
	 * Indicates whether the user agent should send or receive cookies from the other domain in the case of cross-origin requests.
	 */
	credentials?: RequestCredentials;

	/**
	 * The mode of the request (e.g., cors, no-cors, same-origin, etc).
	 */
	mode?: RequestMode;

	/**
	 * The number of milliseconds the request can take before automatically being terminated.
	 * If undefined or value is 0 then there is no timeout.
	 */
	timeout?: number;

	/**
	 * The Common Media Client Data (CMCD) that comprises media and request related information.
	 */
	cmcd?: Cmcd;

	/**
	 * Any custom data.
	 */
	customData?: any;
};
