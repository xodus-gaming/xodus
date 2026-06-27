use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use ntfs::attribute_value::{
    NtfsAttributeListNonResidentAttributeValue, NtfsAttributeValue, NtfsDataRun,
};
use ntfs::{Ntfs, NtfsAttributeType, NtfsFile};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsDataRunReport {
    pub start: Option<u64>,
    pub length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsStreamLayoutReport {
    pub file_record_number: u64,
    pub path: String,
    pub resident_data: bool,
    pub resident_data_length: u64,
    pub value_length: u64,
    pub data_runs: Vec<NtfsDataRunReport>,
}

impl NtfsStreamLayoutReport {
    pub fn is_fragmented_or_embedded(&self) -> bool {
        self.resident_data || self.data_runs.len() > 1
    }
}

pub fn collect_ntfs_stream_layouts<T>(fs: &mut T) -> ntfs::Result<Vec<NtfsStreamLayoutReport>>
where
    T: Read + Seek,
{
    fs.rewind()?;
    let mut ntfs = Ntfs::new(fs)?;
    ntfs.read_upcase_table(fs)?;

    let root = ntfs.root_directory(fs)?;
    let mut reports = Vec::new();
    collect_directory_stream_layouts(&ntfs, fs, &root, Path::new(""), &mut reports)?;
    Ok(reports)
}

pub fn collect_fragmented_or_embedded_ntfs_stream_layouts<T>(
    fs: &mut T,
) -> ntfs::Result<Vec<NtfsStreamLayoutReport>>
where
    T: Read + Seek,
{
    let reports = collect_ntfs_stream_layouts(fs)?;
    Ok(reports
        .into_iter()
        .filter(NtfsStreamLayoutReport::is_fragmented_or_embedded)
        .collect())
}

fn collect_directory_stream_layouts<T>(
    ntfs: &Ntfs,
    fs: &mut T,
    dir: &NtfsFile<'_>,
    base_path: &Path,
    reports: &mut Vec<NtfsStreamLayoutReport>,
) -> ntfs::Result<()>
where
    T: Read + Seek,
{
    let index = dir.directory_index(fs)?;
    let mut entries = index.entries();

    while let Some(entry) = entries.next(fs) {
        let entry = entry?;
        let key = match entry.key() {
            Some(Ok(key)) => key,
            Some(Err(err)) => return Err(err),
            None => continue,
        };
        let name = key.name().to_string_lossy();
        if name == "." || name == ".." {
            continue;
        }

        let path = join_ntfs_path(base_path, name.as_ref());
        let file = entry.to_file(ntfs, fs)?;

        if file.is_directory() {
            collect_directory_stream_layouts(ntfs, fs, &file, &path, reports)?;
        } else {
            collect_file_stream_layouts(fs, &file, &path, reports)?;
        }
    }

    Ok(())
}

pub(crate) fn collect_file_stream_layouts<T>(
    fs: &mut T,
    file: &NtfsFile<'_>,
    path: &Path,
    reports: &mut Vec<NtfsStreamLayoutReport>,
) -> ntfs::Result<()>
where
    T: Read + Seek,
{
    let mut attributes = file.attributes();

    while let Some(item) = attributes.next(fs) {
        let item = item?;
        let attribute = item.to_attribute()?;

        if attribute.ty()? != NtfsAttributeType::Data {
            continue;
        }

        let stream_name = attribute.name()?.to_string_lossy();
        let full_path = if stream_name.is_empty() {
            path.display().to_string()
        } else {
            format!("{}:{}", path.display(), stream_name)
        };
        let value_length = attribute.value_length();
        let value = attribute.value(fs)?;

        let report = match value {
            NtfsAttributeValue::Resident(value) => NtfsStreamLayoutReport {
                file_record_number: file.file_record_number(),
                path: full_path,
                resident_data: value.len() > 0,
                resident_data_length: value.len(),
                value_length,
                data_runs: Vec::new(),
            },
            NtfsAttributeValue::NonResident(value) => NtfsStreamLayoutReport {
                file_record_number: file.file_record_number(),
                path: full_path,
                resident_data: false,
                resident_data_length: 0,
                value_length,
                data_runs: value
                    .data_runs()
                    .map(data_run_report_from_run)
                    .collect::<ntfs::Result<_>>()?,
            },
            NtfsAttributeValue::AttributeListNonResident(value) => NtfsStreamLayoutReport {
                file_record_number: file.file_record_number(),
                path: full_path,
                resident_data: false,
                resident_data_length: 0,
                value_length,
                data_runs: synthesize_data_runs_from_value(
                    fs,
                    value,
                    file.ntfs().cluster_size() as usize,
                )?,
            },
        };

        reports.push(report);
    }

    Ok(())
}

fn synthesize_data_runs_from_value<T>(
    fs: &mut T,
    value: NtfsAttributeListNonResidentAttributeValue<'_, '_>,
    cluster_size: usize,
) -> ntfs::Result<Vec<NtfsDataRunReport>>
where
    T: Read + Seek,
{
    let mut attached = NtfsAttributeValue::AttributeListNonResident(value).attach(fs);
    let mut runs = Vec::new();
    let mut buf = vec![0u8; cluster_size.max(1)];

    loop {
        let start = attached
            .data_position()
            .value()
            .map(|position| position.get());
        let bytes_read = attached.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }

        append_run_segment(&mut runs, start, bytes_read as u64);
    }

    Ok(runs)
}

fn append_run_segment(runs: &mut Vec<NtfsDataRunReport>, start: Option<u64>, length: u64) {
    let Some(last) = runs.last_mut() else {
        runs.push(NtfsDataRunReport { start, length });
        return;
    };

    match (last.start, start) {
        (Some(last_start), Some(start)) if last_start + last.length == start => {
            last.length += length;
        }
        (None, None) => {
            last.length += length;
        }
        _ => runs.push(NtfsDataRunReport { start, length }),
    }
}

fn data_run_report_from_run(
    data_run: ntfs::Result<NtfsDataRun>,
) -> ntfs::Result<NtfsDataRunReport> {
    let data_run = data_run?;
    Ok(NtfsDataRunReport {
        start: data_run
            .data_position()
            .value()
            .map(|position| position.get()),
        length: data_run.allocated_size(),
    })
}

fn join_ntfs_path(base_path: &Path, name: &str) -> PathBuf {
    if base_path.as_os_str().is_empty() {
        PathBuf::from(name)
    } else {
        base_path.join(name)
    }
}
