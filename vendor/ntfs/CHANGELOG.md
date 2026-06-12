# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.4.0] - 2023-06-13

### Added
- Added `Display` implementation for all flags structures

### Changed
- Replaced `NtfsString` by `U16StrLe` from my new `nt-string` crate
- Replaced abandoned `binread` dependency by its `binrw` successor crate
- Upgraded `bitflags` dependency to 2.3.1 (#28)  
  Note that this changes the output of the `Debug` implementation of the flags structures.
  If you need something similar to the previous output, use the new `Display` implementation instead.
- Upgraded `memoffset` dependency to 0.9.0 (#28)

### Fixed
- Fixed broken intra-doc link to `NtfsIndexRoot`


## [0.3.1] - 2023-02-01

### Changed
- Made `NtfsError::InvalidUpdateSequenceNumberRange` message more precise

### Fixed
- Fixed `Record::update_sequence_array_count` calculation and perform safe subtraction (#25, #26)


## [0.3.0] - 2023-01-25

### Added
- Added validation of the attribute length when creating an `NtfsAttribute` object (#23)
- Added tests for resident and non-resident read/seek semantics (#23)

### Changed
- Changed `NtfsFile::data` to look up attribute names case-insensitively (#17)
- Changed `NtfsDataRuns::next` to bail out early if the cluster count of a Data Run is zero (#22, #23)
- Changed `NtfsAttributeListNonResidentAttributeValue::seek` and `NtfsNonResidentAttributeValue::seek` to reset the internal `stream_data_run` (and thereby the external `data_position`) to `None` when seeking beyond the valid total length of an attribute (#22, #23)
- Upgraded `memoffset` dependency to 0.8.0

### Fixed
- Fixed no_std build and added that to CI
- Fixed out-of-bounds access in `NtfsAttribute::non_resident_value_data_and_position` (#20, #23)
- Fixed unsafe `i8` to `u32` conversion in `BiosParameterBlock::record_size` (#20, #23)
- Fixed out-of-bounds access in `Record::update_sequence_offset` (#20, #23)
- Fixed out-of-bounds access in `NtfsAttributeListEntries::next_resident` (#20, #23)
- Fixed infinite loop in `StreamState::read_data_run` when reading zero bytes (#20, #23)
- Fixed addition overflow in `NtfsAttribute::validate_resident_sizes` (#20, #23)
- Fixed potential panic when reading an attribute list (#23)
- Fixed sparse file / sparse Data Run handling broken in 0.2.0
- Fixed formatting when printing information about sparse Data Runs
- Fixed trivial issues reported by clippy of Rust 1.66.1
- Fixed out-of-bounds access in `Record::fixup` (#24)


## [0.2.0] - 2022-04-14

### Added
- Added support for Index Roots that are part of an Attribute List (#7)
- Added support for native sector sizes up to 4K in the BPB and `ntfs-shell`, and use `NTFS_BLOCK_SIZE` instead of the partition's sector size for Record Fixup (#14)

### Changed
- Changed `Ntfs::new` to check BPB-reported sizes more thoroughly and output better error messages (#1, #4)
- Tightened the cluster size and record size limits for safety (#2)
- Introduced `NtfsPosition` for all `position` and `data_position` values
- Replaced `chrono` by the better maintained and no_std compatible `time`
- Updated to Rust 2021, MSRV to 1.60, use new features where appropriate
- Upgraded dependencies

### Fixed
- Fixed accessing attributes of zero length (#6)
- Fixed reading empty volume name strings (#9)
- Fixed accessing Subnode VCN 0 in an Index Allocation that is part of an Attribute List (#10, #11)
- Fixed handling `sectors_per_cluster` for cluster sizes > 64K, up to 2M (#12, #13)


## [0.1.0] - 2022-01-14
- Initial release
