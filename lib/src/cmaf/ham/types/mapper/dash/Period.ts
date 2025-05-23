import type { AdaptationSet } from './AdaptationSet';

/**
 * DASH Period
 *
 * @group CMAF
 * @alpha
 */
export type Period = {
	$: {
		duration: string;
		id?: string;
		start?: string;
	};
	AdaptationSet: AdaptationSet[];
};
