import { parseM3u8 } from '../utils/hls/m3u8.js';
import { uuid } from '../../utils.js';
import { Presentation, SelectionSet, SwitchingSet , AudioTrack, TextTrack,VideoTrack, Track, Segment } from './model/index.js';
import { parseMpd } from '../utils/dash/mpd.js';
import { mapMpdToHam } from './hamMapper.js';
import { formatSegmentUrl , readHLS , formatSegments } from '../utils/hls/hlsMapper.js';
import type { DashManifest } from '../utils/dash/DashManifest.js';
import type { m3u8, PlayList, MediaGroups, SegmentHls } from '../utils/hls/hlsManifest.js';


async function m3u8toHam(hlsManifest:string,url : string) : Promise<Presentation> {
	const parsedM3u8 = parseM3u8(hlsManifest);
	const playlists: PlayList[] = parsedM3u8.playlists;
	const mediaGroupsAudio = parsedM3u8.mediaGroups?.AUDIO;
	const mediaGroupsSubtitles = parsedM3u8.mediaGroups?.SUBTITLES;
	const audioSwitchingSets: SwitchingSet[] = [];
	const audioTracks : AudioTrack[] = [];
	const selectionSets: SelectionSet[] = [];
    

	// Add selection set of type audio
	for (const audio in mediaGroupsAudio) {
		for (const attributes in mediaGroupsAudio[audio]) {
			const language = mediaGroupsAudio[audio][attributes].language;
			const uri = mediaGroupsAudio[audio][attributes].uri;       
			const manifestUrl = formatSegmentUrl(url, uri);
			const audioManifest = await readHLS(manifestUrl);
			const audioParsed = parseM3u8(audioManifest);
			const segments : Segment[] = await formatSegments(audioParsed?.segments);
			const targetDuration = audioParsed?.targetDuration;
			// TODO: retrieve channels, samplerate, bandwidth and codec
			audioTracks.push(new AudioTrack(audio,'AUDIO', '', targetDuration, language, 0, segments,0,0));
			audioSwitchingSets.push(new SwitchingSet(audio, audioTracks));
		}
	}

	selectionSets.push(new SelectionSet(uuid(), audioSwitchingSets));

	const textTracks: TextTrack[] = [];
	const subtitleSwitchingSets: SwitchingSet[] = [];
    
	// Add selection set of type subtitles
	for (const subtitle in mediaGroupsSubtitles) {
		for (const attributes in mediaGroupsSubtitles[subtitle]) {
			const language = mediaGroupsSubtitles[subtitle][attributes].language;
			const uri = mediaGroupsSubtitles[subtitle][attributes].uri;       
			const manifestUrl = formatSegmentUrl(url, uri);
			const subtitleManifest = await readHLS(manifestUrl);
			const subtitleParsed = parseM3u8(subtitleManifest);
			const segments : Segment[] = await formatSegments(subtitleParsed?.segments);
			const targetDuration = subtitleParsed?.targetDuration;
			textTracks.push(new TextTrack(subtitle, 'TEXT','', targetDuration, language, 0, segments));
			subtitleSwitchingSets.push(new SwitchingSet(subtitle, audioTracks));
		}
	}

	if (subtitleSwitchingSets.length > 0) {
		selectionSets.push(new SelectionSet(uuid(), subtitleSwitchingSets));
	}

	//Add selection set of type video
	const switchingSetVideos: SwitchingSet[] = [];

	await Promise.all(playlists.map(async (playlist: any) => {
		const manifestUrl = formatSegmentUrl(url, playlist.uri);
		const hlsManifest = await readHLS(manifestUrl);
		const parsedHlsManifest = parseM3u8(hlsManifest);
		const tracks: Track[] = [];
		const segments : Segment[] = await formatSegments(parsedHlsManifest?.segments);
		const { LANGUAGE, CODECS, BANDWIDTH } = playlist.attributes;
		const targetDuration = parsedHlsManifest?.targetDuration;
		const resolution = { width: playlist.attributes.RESOLUTION.width, height: playlist.attributes.RESOLUTION.height };
		tracks.push(new VideoTrack(uuid(),'VIDEO',CODECS, targetDuration, LANGUAGE, BANDWIDTH,segments,resolution.width,resolution.height,playlist.attributes['FRAME-RATE'],'','',''));
		switchingSetVideos.push(new SwitchingSet(uuid(),tracks));
	}));

	selectionSets.push(new SelectionSet(uuid(), switchingSetVideos));

	return new Presentation(uuid(), selectionSets);

}

function hamToM3u8(presentation: Presentation): m3u8 {
	const playlists: PlayList[] = [];
	let mediaGroups: MediaGroups = { AUDIO: {} };
	const segments: SegmentHls[] = [];
  
	presentation.selectionSets.forEach(selectionSet => {
		selectionSet.switchingSet.forEach(switchingSet => {
			switchingSet.tracks.forEach(track => {
				if (track.type === 'VIDEO' && track.isVideoTrack(track)){
					playlists.push({
						uri: '',
						attributes: {
							CODECS: track.codec,
							BANDWIDTH: track.bandwidth,
							FRAME_RATE: track.frameRate,
							RESOLUTION: { width: track.width, height: track.height },
						},
					});
				} 
				else if (track.type === 'AUDIO') {
					const mediaGroup: MediaGroups = {
						AUDIO: {
							[switchingSet.id]: {
								[track.language]: { language: track.language },
							},
						},
					};
					mediaGroups = { ...mediaGroups, ...mediaGroup };
				}
				segments.push({ duration: switchingSet.tracks[0].duration });
			});
		});
	});
  
	return { playlists, mediaGroups, segments };
}
  
async function mpdToHam(manifest: string): Promise<Presentation | null> {
	let dashManifest: DashManifest | undefined;
	await parseMpd(manifest, (result: DashManifest) => dashManifest = result);

	if (!dashManifest) {
		return null;
	}

	return mapMpdToHam(dashManifest);
}


async function m3u8toHamFromManifest(hlsManifest:string, baseUrl:string) : Promise<Presentation> {
	const hamParsed = await m3u8toHam(hlsManifest,baseUrl);
	return hamParsed;
}

async function m3u8toHamFromUrl(url: string): Promise<Presentation> {
	const hlsManifest: string = await readHLS(url);
	const hamParsed = await m3u8toHam(hlsManifest,url);
	return hamParsed;
}


export { m3u8toHam, m3u8toHamFromManifest, hamToM3u8, mpdToHam, m3u8toHamFromUrl };


