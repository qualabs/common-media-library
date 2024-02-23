import { Track } from './Track.js';
import { Segment } from './Segment.js';
import { ElementVisitor } from '../visitor/ElementVisitor';

export class VideoTrack extends Track {
	width: number;
	height: number;
	frameRate: number;
	par: string;
	sar: string;
	scanType: string;

	constructor(
		id: string,
		type: string,
		codec: string,
		duration: number,
		language: string,
		bandwidth: number,
		segments: Segment[],
		width: number,
		height: number,
		frameRate: number,
		par: string,
		sar: string,
		scanType: string
	) {
		super(id, type, codec, duration, language, bandwidth, segments);
		this.width = width;
		this.height = height;
		this.frameRate = frameRate;
		this.par = par;
		this.sar = sar;
		this.scanType = scanType;
	}

	override accept(visitor: ElementVisitor): void {
		visitor.visitVideoTrack(this);
	}

	static fromJSON(json: any): VideoTrack {
		return new VideoTrack(
			json.id,
			json.type,
			json.codec,
			+json.duration,
			json.language,
			+json.bandwidth,
			json.segments.map((segment: any) => Segment.fromJSON(segment)),
			+json.width,
			+json.height,
			+json.frameRate,
			json.par,
			json.sar,
			json.scanType,
		);
	}
}
