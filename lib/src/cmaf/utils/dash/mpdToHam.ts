import { AdaptationSet, DashManifest, Representation } from './DashManifest.js';
import {
	AudioTrack,
	Presentation,
	Segment,
	SelectionSet,
	SwitchingSet,
	TextTrack,
	Track,
	VideoTrack,
} from '../../ham/types/model/index.js';
import { iso8601DurationToNumber } from '../utils.js';

function createTrack(
	type: string,
	representation: Representation,
	adaptationSet: AdaptationSet,
	duration: number,
	segments: Segment[],
): AudioTrack | VideoTrack | TextTrack {
	if (type === 'video') {
		return {
			bandwidth: +representation.$.bandwidth,
			codec: representation.$.codecs,
			duration: duration,
			frameRate: 0, // TODO: add frameRate
			height: +(representation.$.height ?? 0),
			id: representation.$.id,
			language: adaptationSet.$.lang,
			par: adaptationSet.$.par ?? '',
			sar: adaptationSet.$.sar ?? '',
			scanType: representation.$.scanType,
			segments: segments,
			type: adaptationSet.$.contentType,
			width: +(representation.$.width ?? 0),
		} as VideoTrack;
	} else if (type === 'audio') {
		return {
			bandwidth: +representation.$.bandwidth,
			channels: +(
				adaptationSet.AudioChannelConfiguration![0].$.value ?? 0
			),
			codec: adaptationSet.$.codecs,
			duration: duration,
			id: representation.$.id,
			language: adaptationSet.$.lang,
			sampleRate: +(adaptationSet.$.audioSamplingRate ?? 0),
			segments: segments,
			type: adaptationSet.$.contentType,
		} as AudioTrack;
	} else {
		// if (type === 'text')
		return {
			bandwidth: +representation.$.bandwidth,
			codec: adaptationSet.$.codecs,
			duration: duration,
			id: representation.$.id,
			language: adaptationSet.$.lang,
			segments: segments,
			type: adaptationSet.$.contentType,
		} as TextTrack;
	}
}

function mpdToHam(rawManifest: DashManifest): Presentation[] {
	const presentations: Presentation[] = rawManifest.MPD.Period.map(
		(period) => {
			const duration: number = iso8601DurationToNumber(period.$.duration);
			const url: string = 'url'; // todo: get real url
			const presentationId: string = 'presentation-id'; // todo: handle id

			const selectionSetGroups: { [group: string]: SelectionSet } = {};

			period.AdaptationSet.map((adaptationSet) => {
				const tracks: Track[] = adaptationSet.Representation.map(
					(representation) => {
						const segments = representation.SegmentBase.map(
							(segment) => {
								return {
									duration,
									url,
									byteRange: segment.$.indexRange,
								} as Segment;
							},
						);

						return createTrack(
							adaptationSet.$.contentType,
							representation,
							adaptationSet,
							duration,
							segments,
						);
					},
				);

				if (!selectionSetGroups[adaptationSet.$.group]) {
					selectionSetGroups[adaptationSet.$.group] = {
						id: adaptationSet.$.group,
						switchingSets: [],
					} as SelectionSet;
				}

				selectionSetGroups[adaptationSet.$.group].switchingSets.push({
					id: adaptationSet.$.id,
					tracks,
				} as SwitchingSet);
			});

			const selectionSets: SelectionSet[] =
				Object.values(selectionSetGroups);

			return { id: presentationId, selectionSets } as Presentation;
		},
	);

	return presentations;
}

export { mpdToHam };