import type { AudioTrack } from '../../../types/model/AudioTrack.js';
import type { SwitchingSet } from '../../../types/model/SwitchingSet.js';

import type { Manifest } from '../../../types/manifest/Manifest.js';

import { parseHlsManifest } from '../../../utils/hls/parseHlsManifest.js';

import { formatSegments } from './utils/formatSegments.js';
import { getByterange } from './utils/getByterange.js';
import { getCodec } from './utils/getCodec.js';
import { getDuration } from './utils/getDuration.js';

/**
 * @internal
 *
 * This function is used to convert audio groups to switching sets.
 *
 *
 * @param mediaGroupsAudio - Any
 * @param manifestPlaylists - Array of Manifest
 * @returns Array of switchingSet
 *
 * @group CMAF
 * @alpha
 */
export function audioGroupsToSwitchingSets(
	mediaGroupsAudio: any,
	manifestPlaylists: Manifest[],
): SwitchingSet[] {
	const audioSwitchingSets: SwitchingSet[] = [];
	const audioTracks: AudioTrack[] = [];

	for (const audioEncodings in mediaGroupsAudio) {
		const encodings = mediaGroupsAudio[audioEncodings];
		for (const audio in encodings) {
			const attributes: any = encodings[audio];
			const { language, uri } = attributes;
			const audioParsed = parseHlsManifest(
				manifestPlaylists.shift()?.manifest,
			);
			const map = audioParsed?.segments[0]?.map;
			const segments = formatSegments(audioParsed?.segments);

			// TODO: channels, sampleRate, bandwith and codec need to be
			// updated with real values. Right now we are using simple hardcoded values.
			const byteRange = getByterange(map?.byterange);
			audioTracks.push({
				id: audio,
				type: 'audio',
				fileName: uri,
				codec: getCodec('audio'),
				duration: getDuration(audioParsed, segments),
				language: language,
				bandwidth: 0,
				segments: segments,
				sampleRate: 0,
				channels: 2,
				...(byteRange && { byteRange }),
				...(map?.uri && { urlInitialization: map?.uri }),
			} as AudioTrack);
		}
	}

	audioSwitchingSets.push({
		id: 'audio',
		tracks: audioTracks,
	} as SwitchingSet);

	return audioSwitchingSets;
}
