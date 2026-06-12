// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// It is important to note that `NtfsAttributeListNonResidentAttributeValue` can't just encapsulate `NtfsNonResidentAttributeValue` and provide one
// layer on top to connect the attributes!
// Connected attributes are stored in a way that the first attribute reports the entire data size and all further attributes report a zero value length.
// We have to go down to the Data Run level to get trustable lengths again, and this is what `NtfsAttributeListNonResidentAttributeValue` does here.

use binrw::io::{Read, Seek, SeekFrom};

use super::{DataRunsState, NtfsDataRuns, StreamState};
use crate::attribute::{NtfsAttribute, NtfsAttributeType};
use crate::error::{NtfsError, Result};
use crate::file::NtfsFile;
use crate::ntfs::Ntfs;
use crate::structured_values::{NtfsAttributeListEntries, NtfsAttributeListEntry};
use crate::traits::NtfsReadSeek;
use crate::types::NtfsPosition;

/// Reader for a non-resident attribute value that is part of an Attribute List.
///
/// Such values are not only split up into data runs, but may also be continued by connected attributes
/// which are listed in the same Attribute List.
/// This reader considers that by providing one contiguous data stream for all data runs in all connected attributes.
#[derive(Clone, Debug)]
pub struct NtfsAttributeListNonResidentAttributeValue<'n, 'f> {
    /// Reference to the base `Ntfs` object of this filesystem.
    ntfs: &'n Ntfs,
    /// An untouched copy of the `attribute_list_entries` passed in [`Self::new`] to rewind to the beginning when desired.
    initial_attribute_list_entries: NtfsAttributeListEntries<'n, 'f>,
    /// Iterator through all connected attributes of this attribute in the Attribute List.
    connected_entries: AttributeListConnectedEntries<'n, 'f>,
    /// Total length of the value data, in bytes.
    data_size: u64,
    /// File, location, and data runs iteration state of the current attribute.
    attribute_state: Option<AttributeState<'n>>,
    /// Iteration state of the current Data Run.
    stream_state: StreamState,
}

impl<'n, 'f> NtfsAttributeListNonResidentAttributeValue<'n, 'f> {
    pub(crate) fn new<T>(
        ntfs: &'n Ntfs,
        fs: &mut T,
        attribute_list_entries: NtfsAttributeListEntries<'n, 'f>,
        instance: u16,
        ty: NtfsAttributeType,
        data_size: u64,
    ) -> Result<Self>
    where
        T: Read + Seek,
    {
        let connected_entries =
            AttributeListConnectedEntries::new(attribute_list_entries.clone(), instance, ty);
        let stream_state = StreamState::new(data_size);

        let mut value = Self {
            ntfs,
            initial_attribute_list_entries: attribute_list_entries,
            connected_entries,
            data_size,
            attribute_state: None,
            stream_state,
        };
        value.next_attribute(fs)?;

        Ok(value)
    }

    /// Returns the absolute current data seek position within the filesystem, in bytes.
    /// This may be `None` if:
    ///   * The current seek position is outside the valid range, or
    ///   * The current Data Run is a "sparse" Data Run.
    pub fn data_position(&self) -> NtfsPosition {
        self.stream_state.data_position()
    }

    /// Returns `true` if the non-resident attribute value contains no data.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the total length of the non-resident attribute value data, in bytes.
    pub fn len(&self) -> u64 {
        self.data_size
    }

    /// Advances to the next Data Run and returns whether we got another Data Run.
    fn next_data_run(&mut self) -> Result<bool> {
        // Do we have a file and a (non-resident) attribute to iterate through its data runs?
        let attribute_state = match &mut self.attribute_state {
            Some(attribute_state) => attribute_state,
            None => return Ok(false),
        };

        // Get the state of the `NtfsDataRuns` iterator of that attribute.
        let data_runs_state = match attribute_state.data_runs_state.take() {
            Some(data_runs_state) => data_runs_state,
            None => return Ok(false),
        };

        // Deserialize the state into an `NtfsDataRuns` iterator.
        let attribute = NtfsAttribute::new(
            &attribute_state.file,
            attribute_state.attribute_offset,
            None,
        )?;
        let (data, position) = attribute.non_resident_value_data_and_position()?;
        let mut stream_data_runs =
            NtfsDataRuns::from_state(self.ntfs, data, position, data_runs_state);

        // Do we have a next Data Run? Save that.
        let stream_data_run = match stream_data_runs.next() {
            Some(stream_data_run) => stream_data_run,
            None => return Ok(false),
        };
        let stream_data_run = stream_data_run?;
        self.stream_state.set_stream_data_run(Some(stream_data_run));

        // We got another Data Run, so serialize the updated `NtfsDataRuns` state for the next iteration.
        // This step is skipped when we got no Data Run, because it means we have fully iterated this iterator (and hence also the attribute and file).
        attribute_state.data_runs_state = Some(stream_data_runs.into_state());

        Ok(true)
    }

    /// Advances to the next attribute and returns whether we got another connected attribute.
    fn next_attribute<T>(&mut self, fs: &mut T) -> Result<bool>
    where
        T: Read + Seek,
    {
        // Do we have another connected attribute?
        let entry = match self.connected_entries.next(fs) {
            Some(entry) => entry,
            None => return Ok(false),
        };

        // Read the correspoding File Record into an `NtfsFile` and get the corresponding `NtfsAttribute`.
        let entry = entry?;
        let file = entry.to_file(self.ntfs, fs)?;
        let attribute = entry.to_attribute(&file)?;
        let attribute_offset = attribute.offset();

        // Connected attributes must always be non-resident. Verify that.
        if attribute.is_resident() {
            return Err(NtfsError::UnexpectedResidentAttribute {
                position: attribute.position(),
            });
        }

        // Get an `NtfsDataRuns` iterator for iterating through the attribute value's data runs.
        let (data, position) = attribute.non_resident_value_data_and_position()?;
        let mut stream_data_runs = NtfsDataRuns::new(self.ntfs, data, position);

        // Get the first Data Run already here to save time and let `data_position` return something meaningful.
        let stream_data_run = match stream_data_runs.next() {
            Some(stream_data_run) => stream_data_run,
            None => return Ok(false),
        };
        let stream_data_run = stream_data_run?;
        self.stream_state.set_stream_data_run(Some(stream_data_run));

        // Store the `NtfsFile` and serialize the `NtfsDataRuns` state for a later iteration.
        let data_runs_state = Some(stream_data_runs.into_state());
        self.attribute_state = Some(AttributeState {
            file,
            attribute_offset,
            data_runs_state,
        });

        Ok(true)
    }

    /// Returns the [`Ntfs`] object reference associated to this value.
    pub fn ntfs(&self) -> &'n Ntfs {
        self.ntfs
    }

    /// Rewinds this value reader to the very beginning.
    fn rewind<T>(&mut self, fs: &mut T) -> Result<()>
    where
        T: Read + Seek,
    {
        self.connected_entries.attribute_list_entries =
            Some(self.initial_attribute_list_entries.clone());
        self.stream_state = StreamState::new(self.len());
        self.next_attribute(fs)?;

        Ok(())
    }
}

impl<'n, 'f> NtfsReadSeek for NtfsAttributeListNonResidentAttributeValue<'n, 'f> {
    fn read<T>(&mut self, fs: &mut T, buf: &mut [u8]) -> Result<usize>
    where
        T: Read + Seek,
    {
        let mut bytes_read = 0usize;

        while bytes_read < buf.len() {
            // Read from the current Data Run if there is one.
            if self.stream_state.read_data_run(fs, buf, &mut bytes_read)? {
                // We read something, so check the loop condition again if we need to read more.
                continue;
            }

            // Move to the next Data Run of the current attribute.
            if self.next_data_run()? {
                // We got another Data Run of the current attribute, so read again.
                continue;
            }

            // Move to the first Data Run of the next connected attribute.
            if self.next_attribute(fs)? {
                // We got another attribute, so read again.
                continue;
            } else {
                // We read everything we could.
                break;
            }
        }

        Ok(bytes_read)
    }

    fn seek<T>(&mut self, fs: &mut T, pos: SeekFrom) -> Result<u64>
    where
        T: Read + Seek,
    {
        let pos = self.stream_state.optimize_seek(pos, self.len())?;

        let mut bytes_left_to_seek = match pos {
            SeekFrom::Start(n) => {
                self.rewind(fs)?;
                n
            }
            SeekFrom::Current(n) if n >= 0 => n as u64,
            _ => unreachable!(),
        };

        while bytes_left_to_seek > 0 {
            // Seek inside the current Data Run if there is one.
            if self
                .stream_state
                .seek_data_run(fs, pos, &mut bytes_left_to_seek)?
            {
                // We have reached our final seek position.
                break;
            }

            // Move to the next Data Run of the current attribute.
            if self.next_data_run()? {
                // We got another Data Run of the current attribute, so seek some more.
                continue;
            }

            // Move to the first Data Run of the next connected attribute.
            if self.next_attribute(fs)? {
                // We got another connected attribute, so seek some more.
                continue;
            } else {
                // We seeked as far as we could.
                self.stream_state.set_stream_data_run(None);
                break;
            }
        }

        match pos {
            SeekFrom::Start(n) => self.stream_state.set_stream_position(n),
            SeekFrom::Current(n) => self
                .stream_state
                .set_stream_position(self.stream_position() + n as u64),
            _ => unreachable!(),
        }

        Ok(self.stream_position())
    }

    fn stream_position(&self) -> u64 {
        self.stream_state.stream_position()
    }
}

#[derive(Clone, Debug)]
struct AttributeListConnectedEntries<'n, 'f> {
    attribute_list_entries: Option<NtfsAttributeListEntries<'n, 'f>>,
    instance: u16,
    ty: NtfsAttributeType,
}

impl<'n, 'f> AttributeListConnectedEntries<'n, 'f> {
    fn new(
        attribute_list_entries: NtfsAttributeListEntries<'n, 'f>,
        instance: u16,
        ty: NtfsAttributeType,
    ) -> Self {
        Self {
            attribute_list_entries: Some(attribute_list_entries),
            instance,
            ty,
        }
    }

    fn next<T>(&mut self, fs: &mut T) -> Option<Result<NtfsAttributeListEntry>>
    where
        T: Read + Seek,
    {
        let attribute_list_entries = self.attribute_list_entries.as_mut()?;

        let entry = iter_try!(attribute_list_entries.next(fs)?);
        if entry.instance() == self.instance && iter_try!(entry.ty()) == self.ty {
            Some(Ok(entry))
        } else {
            self.attribute_list_entries = None;
            None
        }
    }
}

#[derive(Clone, Debug)]
struct AttributeState<'n> {
    file: NtfsFile<'n>,
    attribute_offset: usize,
    /// We cannot store an `NtfsDataRuns` here, because it has a reference to the `NtfsFile` that is also stored here.
    /// This is why we have to go via `DataRunsState` in an `Option` to take() it and deserialize it into an `NtfsDataRuns` whenever necessary.
    data_runs_state: Option<DataRunsState>,
}
