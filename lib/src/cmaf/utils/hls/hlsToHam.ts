import { parseHlsManifest } from './hlsParser.js';
import { uuid } from '../../../utils.js';
import {
	AudioTrack,
	TextTrack,
	Segment,
	SelectionSet,
	SwitchingSet,
	Track,
	VideoTrack,
} from '../../ham/types/model/index.js';
import { addMetadataToHls } from '../manifestUtils.js';
import { PlayList } from '../../ham/types/HlsManifest.js';
import { Manifest } from '../../ham/types/index.js';

function hlsToHam(manifest: Manifest) {
	const mainManifestParsed = parseHlsManifest(manifest.manifest);
	manifest = addMetadataToHls(manifest, mainManifestParsed);
	const playlists: PlayList[] = mainManifestParsed.playlists;
	const mediaGroupsAudio = mainManifestParsed.mediaGroups?.AUDIO;
	const mediaGroupsSubtitles = mainManifestParsed.mediaGroups?.SUBTITLES;
	const audioSwitchingSets: SwitchingSet[] = [];
	const selectionSets: SelectionSet[] = [];
	const manifestPlaylists = manifest.ancillaryManifests
		? manifest.ancillaryManifests
		: [];
	let currentPlaylist = 0;

	for (const audio in mediaGroupsAudio) {
		const audioTracks: AudioTrack[] = [];
		const attributes: any = mediaGroupsAudio[audio];
		const keys = Object.keys(attributes);
		const { language, uri } = attributes[keys[0]];
		const audioParsed = parseHlsManifest(
			manifestPlaylists[currentPlaylist++].manifest,
		);
		const segments: Segment[] = _formatSegments(audioParsed?.segments);
		const targetDuration = audioParsed?.targetDuration;
		const map = audioParsed.segments[0]?.map;
		const byteRange =
			map && map.byterange
				? `${map.byterange.length}@${map.byterange.offset}`
				: undefined;
		// TODO: retrieve channels, samplerate, bandwidth and codec
		audioTracks.push({
			id: audio,
			type: 'audio',
			name: uri,
			codec: '',
			duration: targetDuration,
			language: language,
			bandwidth: 0,
			segments: segments,
			sampleRate: 0,
			channels: 0,
			byteRange: byteRange,
			urlInitialization: map?.uri,
		} as AudioTrack);
		audioSwitchingSets.push({
			id: audio,
			tracks: audioTracks,
		} as SwitchingSet);
	}

	selectionSets.push({
		id: uuid(),
		switchingSets: audioSwitchingSets,
	} as SelectionSet);

	const subtitleSwitchingSets: SwitchingSet[] = [];

	// Add selection set of type subtitles
	for (const subtitle in mediaGroupsSubtitles) {
		const attributes = mediaGroupsSubtitles[subtitle];
		const textTracks: TextTrack[] = [];
		const keys = Object.keys(attributes);
		const { language, uri } = attributes[keys[0]];
		const subtitleParsed = parseHlsManifest(
			manifestPlaylists[currentPlaylist++].manifest,
		);
		const segments: Segment[] = _formatSegments(subtitleParsed?.segments);
		const targetDuration = subtitleParsed?.targetDuration;
		textTracks.push({
			id: subtitle,
			type: 'text',
			name: uri,
			codec: '',
			duration: targetDuration,
			language: language,
			bandwidth: 0,
			segments: segments,
		} as TextTrack);
		subtitleSwitchingSets.push({
			id: subtitle,
			tracks: textTracks,
		} as SwitchingSet);
	}

	if (subtitleSwitchingSets.length > 0) {
		selectionSets.push({
			id: uuid(),
			switchingSets: subtitleSwitchingSets,
		} as SelectionSet);
	}

	//Add selection set of type video
	const switchingSetVideos: SwitchingSet[] = [];

	playlists.map(async (playlist: any) => {
		const parsedHlsManifest = parseHlsManifest(
			manifestPlaylists[currentPlaylist++].manifest,
		);
		const tracks: Track[] = [];
		const segments: Segment[] = _formatSegments(
			parsedHlsManifest?.segments,
		);
		const { LANGUAGE, CODECS, BANDWIDTH } = playlist.attributes;
		const targetDuration = parsedHlsManifest?.targetDuration;
		const resolution = {
			width: playlist.attributes.RESOLUTION.width,
			height: playlist.attributes.RESOLUTION.height,
		};
		const map = parsedHlsManifest.segments[0]?.map;
		const byterange = map?.byterange;
		const uri = map?.uri;
		tracks.push({
			id: uuid(),
			type: 'video',
			name: playlist.uri,
			codec: CODECS,
			duration: targetDuration,
			language: LANGUAGE,
			bandwidth: BANDWIDTH,
			segments: segments,
			width: resolution.width,
			height: resolution.height,
			frameRate: playlist.attributes['FRAME-RATE'],
			par: '',
			sar: '',
			scanType: '',
			byteRange: byterange
				? `${byterange.length}@${byterange.offset}`
				: undefined,
			urlInitialization: uri,
		} as VideoTrack);

		switchingSetVideos.push({
			id: uuid(),
			tracks: tracks,
		} as SwitchingSet);
	});

	selectionSets.push({
		id: uuid(),
		switchingSets: switchingSetVideos,
	} as SelectionSet);

	const presentations = [{ id: uuid(), selectionSets: selectionSets }];
	return presentations;
}

function _formatSegments(segments: any[]) {
	const formattedSegments: Segment[] = [];
	segments.map(async (segment: any) => {
		const { duration, uri } = segment;
		const { length, offset } = segment.byterange
			? segment.byterange
			: { length: 0, offset: 0 };
		formattedSegments.push({
			duration: duration,
			url: uri,
			byteRange: length ? `${length}@${offset}` : undefined,
		} as Segment);
	});

	return formattedSegments;
}

export { hlsToHam };