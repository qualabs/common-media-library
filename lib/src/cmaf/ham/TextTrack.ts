import { Track } from './Track.js';
import { Segment } from './Segment.js';

export class TextTrack extends Track {

	constructor(
		id: string,
		codec: string,
		duration: number,
		language: string,
		bandwidth: number,
		segments: Segment[],
	) {
		super(id, codec, duration, language, bandwidth, segments);
		this.id = id;
		this.codec = codec;
		this.duration = duration;
		this.language = language;
		this.bandwidth = bandwidth;
		this.segments = segments;
	}

}
