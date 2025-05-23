import type { AudioChannelConfiguration } from './AudioChannelConfiguration';
import type { SegmentBase } from './SegmentBase';
import type { SegmentList } from './SegmentList';
import type { SegmentTemplate } from './SegmentTemplate';

/**
 * DASH Representation
 *
 * @group CMAF
 * @alpha
 */
export type Representation = {
	$: {
		audioSamplingRate?: string;
		bandwidth: string;
		codecs?: string;
		frameRate?: string;
		height?: string;
		id: string;
		mimeType?: string;
		sar?: string;
		scanType?: string;
		startWithSAP?: string;
		width?: string;
	};
	AudioChannelConfiguration?: AudioChannelConfiguration[];
	BaseURL?: string[];
	SegmentBase?: SegmentBase[];
	SegmentList?: SegmentList[];
	SegmentTemplate?: SegmentTemplate[];
};
