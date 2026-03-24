import { validateC2paInitSegment } from '@svta/cml-c2pa'
import { rejects } from 'node:assert'
import { describe, it } from 'node:test'

describe('validateC2paInitSegment', () => {
	// #region example
	it('throws for empty bytes (no C2PA UUID box)', async () => {
		await rejects(
			() => validateC2paInitSegment(new Uint8Array(0)),
			/No C2PA UUID box/,
		)
	})
	// #endregion example

	it('throws when the segment contains an mdat box', async () => {
		// ftyp box (12 bytes) + mdat box (8 bytes) — valid BMFF, no UUID/C2PA
		const ftyp = new Uint8Array([0, 0, 0, 12, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d])
		const mdat = new Uint8Array([0, 0, 0, 8, 0x6d, 0x64, 0x61, 0x74])
		const segment = new Uint8Array(ftyp.length + mdat.length)
		segment.set(ftyp, 0)
		segment.set(mdat, ftyp.length)
		await rejects(
			() => validateC2paInitSegment(segment),
			/mdat/,
		)
	})

})
