# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-24

### Added

- `readC2paManifest` — parse C2PA manifest store from BMFF bytes (supports both JUMBF UUID per ISO 19566-5 and C2PA-specific UUID)
- `extractManifestCertificate` — extract DER certificate from COSE_Sign1 x5chain header
- `validateC2paInitSegment` — validate init segment: manifest, certificate, BMFF hash, session keys
- `validateC2paSegment` — validate media segment: COSE signature, BMFF hash, sequence number, key expiry
- `validateC2paManifestBoxSegment` — validate manifest-box segment: parse, chain validation, assertions
- `decodeCoseSign1` — decode COSE_Sign1 structure (RFC 9052)
- `decodeVsiMap` — decode CBOR VSI map from COSE payload
- `parseEmsgBox` / `extractVsiEmsgBox` — parse EMSG boxes (ISO 14496-12) for `urn:c2pa:verifiable-segment-info`
- `validateSequenceNumber` / `createSequenceState` — stateless sequence number validation per C2PA Live Streaming §18.4
- `computeBmffHash` / `validateBmffHash` — BMFF content hash computation and validation with XPath exclusions
- Full type exports: `C2paManifestStore`, `C2paManifest`, `C2paAssertion`, `CoseSign1`, `VsiMap`, `SequenceState`, `InitSegmentValidation`, `SegmentValidationResult`, `ManifestBoxValidationResult`, and others

[Unreleased]: https://github.com/streaming-video-technology-alliance/common-media-library/compare/c2pa-v0.1.0...HEAD
[0.1.0]: https://github.com/streaming-video-technology-alliance/common-media-library/tree/c2pa-v0.1.0
