import type { AdaptationSet } from '../../../types/mapper/dash/AdaptationSet.js';
import type { Representation } from '../../../types/mapper/dash/Representation.js';
import type { SegmentList } from '../../../types/mapper/dash/SegmentList.js';
import type { SegmentTemplate } from '../../../types/mapper/dash/SegmentTemplate.js';

import type { Segment } from '../../../types/model/Segment.js';

import { mapSegmentBase } from './mapSegmentBase.js';
import { mapSegmentList } from './mapSegmentList.js';
import { mapSegmentTemplate } from './mapSegmentTemplate.js';

/**
 * @internal
 *
 * Maps dash segments to ham segment.
 *
 * Checks the type of dash segments used to map them accordingly.
 * @see mapSegmentBase
 * @see mapSegmentList
 * @see mapSegmentTemplate
 *
 * @param adaptationSet - AdaptationSet to get the segments from
 * @param representation - Representation to get the segments from
 * @param duration - Duration of the segments
 * @returns list of ham segments
 */
export function mapSegments(
	adaptationSet: AdaptationSet,
	representation: Representation,
	duration: number,
): Segment[] {
	const segmentTemplate: SegmentTemplate | undefined =
		adaptationSet.SegmentTemplate?.at(0) ??
		representation.SegmentTemplate?.at(0);
	const segmentList: SegmentList[] | undefined =
		adaptationSet.SegmentList ?? representation.SegmentList;
	if (representation.SegmentBase) {
		return mapSegmentBase(representation, duration);
	}
	else if (segmentList) {
		return mapSegmentList(segmentList);
	}
	else if (segmentTemplate) {
		return mapSegmentTemplate(representation, duration, segmentTemplate);
	}
	else {
		console.error(`Representation ${representation.$.id} has no segments`);
		return [] as Segment[];
	}
}
