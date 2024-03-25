import { equal } from 'node:assert';
import { describe, it } from 'node:test';
import { parseM3u8ContentSteeringURI } from '../../src/contentsteering/parseM3u8ContentSteeringURI.js';

describe('parseM3u8ContentSteeringURI', () => {
	it('should parse M3U8 manifest and extract content steering server URI', () => {
		const manifest: string = `#EXT-X-CONTENT-STEERING:SERVER-URI='http://example.com'`;

		const expectedURI: string = 'http://example.com';
		console.log(parseM3u8ContentSteeringURI(manifest), 'COLOCALE REPARAR RAPIDO');

		equal(parseM3u8ContentSteeringURI(manifest), expectedURI);
	});

	it('should return null if content steering server URI is not found', () => {
		const manifest: string = `
      #EXTM3U
      #EXT-X-VERSION:3
      #EXT-X-TARGETDURATION:10
      #EXTINF:10.0,
      example.ts
    `;

		// const result: string | null = await parseM3u8ContentSteeringURI(manifest);
		// expect(result).toBeNull();
		equal(parseM3u8ContentSteeringURI(manifest), null);

	});

	it('should return null if manifest is empty', () => {
		const manifest: string = '';
		// const result: string | null = await parseM3u8ContentSteeringURI(manifest);
		// expect(result).toBeNull();
		equal(parseM3u8ContentSteeringURI(manifest), null);
	});

	it('should return null if manifest is invalid', () => {
		const manifest: string = 'Invalid manifest';
		// const result: string | null = await parseM3u8ContentSteeringURI(manifest);
		// expect(result).toBeNull();
		equal(parseM3u8ContentSteeringURI(manifest), null);

	});
});
