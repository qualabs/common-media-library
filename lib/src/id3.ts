/**
 * @groupDescription ID3
 * A collection of tools for working with ID3v2 tags.
 *
 * @see {@link https://mutagen-specs.readthedocs.io/en/latest/id3/id3v2.4.0-structure.html | ID3v2.4.0 Structure}
 * @see {@link https://mutagen-specs.readthedocs.io/en/latest/id3/id3v2.4.0-frames.html | ID3v2.4.0 Frames}
 *
 * @packageDocumentation
 */
export { canParseId3 } from './id3/canParseId3.ts';
export type { DecodedId3Frame } from './id3/DecodedId3Frame.ts';
export { getId3Data } from './id3/getId3Data.ts';
export { getId3Frames } from './id3/getId3Frames.ts';
export { getId3Timestamp } from './id3/getId3Timestamp.ts';
export { ID3_SCHEME_ID_URI } from './id3/ID3_SCHEME_ID_URI.ts';
export type { Id3Frame } from './id3/Id3Frame.ts';
export { isId3TimestampFrame } from './id3/isId3TimestampFrame.ts';
