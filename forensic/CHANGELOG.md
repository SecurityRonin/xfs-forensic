# Changelog

All notable changes to `xfs-forensic` (the analyzer) are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/SecurityRonin/xfs-forensic/compare/xfs-forensic-v0.1.4...xfs-forensic-v0.2.0) - 2026-11-12

### Added

- *(xattr)* GREEN - decode the XFS attribute fork; fix 64-bit extent counters

### Documentation

- *(forensic)* [**breaking**] record that xfs-core types in our API make this breaking

## [0.1.2]

- Current published analyzer: anomaly auditing over XFS structures, emitting
  `forensicnomicon::report::Finding`s.

<!-- release-plz appends new versions above this line, newest first. -->
