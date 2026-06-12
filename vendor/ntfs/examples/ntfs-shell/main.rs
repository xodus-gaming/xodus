// Copyright 2021-2023 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

mod sector_reader;

use std::env;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{BufReader, Read, Seek, Write};

use anyhow::{anyhow, bail, Context, Result};
use ntfs::attribute_value::NtfsAttributeValue;
use ntfs::indexes::NtfsFileNameIndex;
use ntfs::structured_values::{
    NtfsAttributeList, NtfsFileName, NtfsFileNamespace, NtfsStandardInformation,
};
use ntfs::{Ntfs, NtfsAttribute, NtfsAttributeType, NtfsFile, NtfsReadSeek};
use time::format_description::FormatItem;
use time::macros::format_description;
use time::OffsetDateTime;

use sector_reader::SectorReader;

struct CommandInfo<'n, T>
where
    T: Read + Seek,
{
    current_directory: Vec<NtfsFile<'n>>,
    current_directory_string: String,
    fs: T,
    ntfs: &'n Ntfs,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: ntfs-shell FILESYSTEM");
        eprintln!();
        eprintln!("FILESYSTEM can be a path to any NTFS filesystem image.");
        eprintln!("Under Windows and when run with administrative privileges, FILESYSTEM can also");
        eprintln!("be the special path \\\\.\\C: to access the filesystem of the C: partition.");
        bail!("Aborted");
    }

    let f = File::open(&args[1])?;
    let sr = SectorReader::new(f, 4096)?;
    let mut fs = BufReader::new(sr);
    let mut ntfs = Ntfs::new(&mut fs)?;
    ntfs.read_upcase_table(&mut fs)?;
    let current_directory = vec![ntfs.root_directory(&mut fs)?];

    let mut info = CommandInfo {
        current_directory,
        current_directory_string: String::new(),
        fs,
        ntfs: &ntfs,
    };

    println!("**********************************************************************");
    println!("ntfs-shell - Demonstration of the ntfs Rust crate");
    println!("by Colin Finck <colin@reactos.org>");
    println!("**********************************************************************");
    println!();
    println!("Opened \"{}\" read-only.", args[1]);
    println!();

    loop {
        print!("ntfs-shell:\\{}> ", info.current_directory_string);
        io::stdout().flush()?;

        let mut input_string = String::new();
        io::stdin().read_line(&mut input_string).unwrap();
        if input_string.is_empty() {
            // An empty `input_string` without even a newline looks like STDIN was closed.
            break;
        }

        let input = input_string.trim();
        let mid = input.find(' ').unwrap_or(input.len());
        let (command, arg) = input.split_at(mid);
        let arg = arg.trim_start();

        let result = match command {
            "attr" => attr(false, arg, &mut info),
            "attr_runs" => attr(true, arg, &mut info),
            "cd" => cd(arg, &mut info),
            "dir" => dir(&mut info),
            "exit" | "quit" => break,
            "fileinfo" => fileinfo(arg, &mut info),
            "fsinfo" => fsinfo(&mut info),
            "get" => get(arg, &mut info),
            "help" => help(arg),
            "" => continue,
            _ => Err(anyhow!(
                "Invalid command \"{}\". Type \"help\" to get a list of all commands.",
                command
            )),
        };
        if let Err(e) = result {
            eprintln!("Error: {e:?}");
        }
    }

    Ok(())
}

#[allow(clippy::print_literal)]
fn attr<T>(with_runs: bool, arg: &str, info: &mut CommandInfo<T>) -> Result<()>
where
    T: Read + Seek,
{
    let file = parse_file_arg(arg, info)?;

    println!("{:=<110}", "");
    println!(
        "{:<10} | {:<20} | {:<8} | {:<13} | {:<18} | {:<13} | {}",
        "INSTANCE", "TYPE", "RESIDENT", "RECORD NUMBER", "START", "LENGTH", "NAME"
    );
    println!("{:=<110}", "");

    let attributes = file.attributes_raw();
    for attribute in attributes {
        let attribute = attribute?;
        let ty = attribute.ty()?;

        attr_print_attribute(
            info,
            with_runs,
            &attribute,
            file.file_record_number(),
            "● ",
            "  ■ ",
        )?;

        if ty == NtfsAttributeType::AttributeList {
            let list = attribute.structured_value::<_, NtfsAttributeList>(&mut info.fs)?;
            let mut list_iter = list.entries();

            while let Some(entry) = list_iter.next(&mut info.fs) {
                let entry = entry?;

                let entry_record_number = entry.base_file_reference().file_record_number();
                if entry_record_number == file.file_record_number() {
                    continue;
                }

                let entry_file = entry.to_file(info.ntfs, &mut info.fs)?;
                let entry_attribute = entry.to_attribute(&entry_file)?;

                attr_print_attribute(
                    info,
                    with_runs,
                    &entry_attribute,
                    entry_record_number,
                    "  ○ ",
                    "    □ ",
                )?;
            }
        }
    }

    Ok(())
}

#[allow(clippy::uninlined_format_args)]
fn attr_print_attribute<T>(
    info: &mut CommandInfo<T>,
    with_runs: bool,
    attribute: &NtfsAttribute,
    record_number: u64,
    attribute_prefix: &str,
    data_run_prefix: &str,
) -> Result<()>
where
    T: Read + Seek,
{
    let instance = format!("{attribute_prefix}{}", attribute.instance());
    let ty = attribute.ty()?;
    let resident = attribute.is_resident();
    let start = attribute.position();
    let length = attribute.value_length();
    let name = attribute.name()?.to_string_lossy();

    println!(
        "{:<10} | {:<20} | {:<8} | {:>#13x} | {:>#18x} | {:>13} | \"{}\"",
        instance, ty, resident, record_number, start, length, name
    );

    if with_runs {
        let value = attribute.value(&mut info.fs)?;

        if let NtfsAttributeValue::NonResident(non_resident_value) = value {
            for (i, data_run) in non_resident_value.data_runs().enumerate() {
                let data_run = data_run?;
                let instance = format!("{data_run_prefix}{i}");
                let start = data_run.data_position();
                let length = data_run.allocated_size();

                println!(
                    "{:<10} | {:<20} | {:<8} | {:>13} | {:>#18x} | {:>13} |",
                    instance, "DataRun", "", "", start, length
                );
            }
        }
    }

    Ok(())
}

fn best_file_name<T>(
    info: &mut CommandInfo<T>,
    file: &NtfsFile,
    parent_record_number: u64,
) -> Result<NtfsFileName>
where
    T: Read + Seek,
{
    // Try to find a long filename (Win32) first.
    // If we don't find one, the file may only have a single short name (Win32AndDos).
    // If we don't find one either, go with any namespace. It may still be a Dos or Posix name then.
    let priority = [
        Some(NtfsFileNamespace::Win32),
        Some(NtfsFileNamespace::Win32AndDos),
        None,
    ];

    for match_namespace in priority {
        if let Some(file_name) =
            file.name(&mut info.fs, match_namespace, Some(parent_record_number))
        {
            let file_name = file_name?;
            return Ok(file_name);
        }
    }

    bail!(
        "Found no FileName attribute for File Record {:#x}",
        file.file_record_number()
    )
}

fn cd<T>(arg: &str, info: &mut CommandInfo<T>) -> Result<()>
where
    T: Read + Seek,
{
    if arg.is_empty() {
        return Ok(());
    }

    if arg == ".." {
        if info.current_directory_string.is_empty() {
            return Ok(());
        }

        info.current_directory.pop();

        let new_len = info.current_directory_string.rfind('\\').unwrap_or(0);
        info.current_directory_string.truncate(new_len);
    } else {
        let index = info
            .current_directory
            .last()
            .unwrap()
            .directory_index(&mut info.fs)?;
        let mut finder = index.finder();
        let maybe_entry = NtfsFileNameIndex::find(&mut finder, info.ntfs, &mut info.fs, arg);

        if maybe_entry.is_none() {
            println!("Cannot find subdirectory \"{arg}\".");
            return Ok(());
        }

        let entry = maybe_entry.unwrap()?;
        let file_name = entry
            .key()
            .expect("key must exist for a found Index Entry")?;

        if !file_name.is_directory() {
            println!("\"{arg}\" is not a directory.");
            return Ok(());
        }

        let file = entry.to_file(info.ntfs, &mut info.fs)?;
        let file_name = best_file_name(
            info,
            &file,
            info.current_directory.last().unwrap().file_record_number(),
        )?;
        if !info.current_directory_string.is_empty() {
            info.current_directory_string += "\\";
        }
        info.current_directory_string += &file_name.name().to_string_lossy();

        info.current_directory.push(file);
    }

    Ok(())
}

fn dir<T>(info: &mut CommandInfo<T>) -> Result<()>
where
    T: Read + Seek,
{
    let index = info
        .current_directory
        .last()
        .unwrap()
        .directory_index(&mut info.fs)?;
    let mut iter = index.entries();

    while let Some(entry) = iter.next(&mut info.fs) {
        let entry = entry?;
        let file_name = entry
            .key()
            .expect("key must exist for a found Index Entry")?;

        let prefix = if file_name.is_directory() {
            "<DIR>"
        } else {
            ""
        };
        println!("{:5}  {}", prefix, file_name.name());
    }

    Ok(())
}

fn fileinfo<T>(arg: &str, info: &mut CommandInfo<T>) -> Result<()>
where
    T: Read + Seek,
{
    let file = parse_file_arg(arg, info)?;

    println!("{:=^72}", " FILE RECORD ");
    println!("{:34}{}", "Allocated Size:", file.allocated_size());
    println!("{:34}{:#x}", "Byte Position:", file.position());
    println!("{:34}{}", "Data Size:", file.data_size());
    println!("{:34}{}", "Hard-Link Count:", file.hard_link_count());
    println!("{:34}{}", "Is Directory:", file.is_directory());
    println!("{:34}{:#x}", "Record Number:", file.file_record_number());
    println!("{:34}{}", "Sequence Number:", file.sequence_number());

    let mut attributes = file.attributes();
    while let Some(attribute_item) = attributes.next(&mut info.fs) {
        let attribute_item = attribute_item?;
        let attribute = attribute_item.to_attribute()?;

        match attribute.ty() {
            Ok(NtfsAttributeType::StandardInformation) => fileinfo_std(attribute)?,
            Ok(NtfsAttributeType::FileName) => fileinfo_filename(info, attribute)?,
            Ok(NtfsAttributeType::Data) => fileinfo_data(attribute)?,
            _ => continue,
        }
    }

    Ok(())
}

fn fileinfo_std(attribute: NtfsAttribute) -> Result<()> {
    const TIME_FORMAT: &[FormatItem] =
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC");

    println!();
    println!("{:=^72}", " STANDARD INFORMATION ");

    let std_info = attribute.resident_structured_value::<NtfsStandardInformation>()?;

    println!("{:34}{}", "Attributes:", std_info.file_attributes());

    let atime = OffsetDateTime::from(std_info.access_time())
        .format(TIME_FORMAT)
        .unwrap();
    let ctime = OffsetDateTime::from(std_info.creation_time())
        .format(TIME_FORMAT)
        .unwrap();
    let mtime = OffsetDateTime::from(std_info.modification_time())
        .format(TIME_FORMAT)
        .unwrap();
    let mmtime = OffsetDateTime::from(std_info.mft_record_modification_time())
        .format(TIME_FORMAT)
        .unwrap();
    println!("{:34}{}", "Access Time:", atime);
    println!("{:34}{}", "Creation Time:", ctime);
    println!("{:34}{}", "Modification Time:", mtime);
    println!("{:34}{}", "MFT Record Modification Time:", mmtime);

    // NTFS 3.x extended information
    let class_id = std_info
        .class_id()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "<NONE>".to_string());
    let maximum_versions = std_info
        .maximum_versions()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "<NONE>".to_string());
    let owner_id = std_info
        .owner_id()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "<NONE>".to_string());
    let quota_charged = std_info
        .quota_charged()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "<NONE>".to_string());
    let security_id = std_info
        .security_id()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "<NONE>".to_string());
    let usn = std_info
        .usn()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "<NONE>".to_string());
    let version = std_info
        .version()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "<NONE>".to_string());
    println!("{:34}{}", "Class ID:", class_id);
    println!("{:34}{}", "Maximum Versions:", maximum_versions);
    println!("{:34}{}", "Owner ID:", owner_id);
    println!("{:34}{}", "Quota Charged:", quota_charged);
    println!("{:34}{}", "Security ID:", security_id);
    println!("{:34}{}", "USN:", usn);
    println!("{:34}{}", "Version:", version);

    Ok(())
}

fn fileinfo_filename<T>(info: &mut CommandInfo<T>, attribute: NtfsAttribute) -> Result<()>
where
    T: Read + Seek,
{
    println!();
    println!("{:=^72}", " FILE NAME ");

    let file_name = attribute.structured_value::<_, NtfsFileName>(&mut info.fs)?;

    println!("{:34}\"{}\"", "Name:", file_name.name().to_string_lossy());
    println!("{:34}{:?}", "Namespace:", file_name.namespace());
    println!(
        "{:34}{:#x}",
        "Parent Directory Record Number:",
        file_name.parent_directory_reference().file_record_number()
    );

    Ok(())
}

fn fileinfo_data(attribute: NtfsAttribute) -> Result<()> {
    println!();
    println!("{:=^72}", " DATA STREAM ");

    println!("{:34}\"{}\"", "Name:", attribute.name()?.to_string_lossy());
    println!("{:34}{}", "Size:", attribute.value_length());

    Ok(())
}

fn fsinfo<T>(info: &mut CommandInfo<T>) -> Result<()>
where
    T: Read + Seek,
{
    println!("{:20}{}", "Cluster Size:", info.ntfs.cluster_size());
    println!("{:20}{}", "File Record Size:", info.ntfs.file_record_size());
    println!("{:20}{:#x}", "MFT Byte Position:", info.ntfs.mft_position());

    let volume_info = info.ntfs.volume_info(&mut info.fs)?;
    let ntfs_version = format!(
        "{}.{}",
        volume_info.major_version(),
        volume_info.minor_version()
    );
    println!("{:20}{}", "NTFS Version:", ntfs_version);

    println!("{:20}{}", "Sector Size:", info.ntfs.sector_size());
    println!("{:20}{}", "Serial Number:", info.ntfs.serial_number());
    println!("{:20}{}", "Size:", info.ntfs.size());

    let volume_name = if let Some(Ok(volume_name)) = info.ntfs.volume_name(&mut info.fs) {
        format!("\"{}\"", volume_name.name())
    } else {
        "<NONE>".to_string()
    };
    println!("{:20}{}", "Volume Name:", volume_name);

    Ok(())
}

fn get<T>(arg: &str, info: &mut CommandInfo<T>) -> Result<()>
where
    T: Read + Seek,
{
    // Extract any specific $DATA stream name from the file.
    let (file_name, data_stream_name) = match arg.find(':') {
        Some(mid) => (&arg[..mid], &arg[mid + 1..]),
        None => (arg, ""),
    };

    // Compose the output file name and try to create it.
    // It must not yet exist, as we don't want to accidentally overwrite things.
    let output_file_name = if data_stream_name.is_empty() {
        file_name.to_string()
    } else {
        format!("{file_name}_{data_stream_name}")
    };
    let mut output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_file_name)
        .with_context(|| format!("Tried to open \"{output_file_name}\" for writing"))?;

    // Open the desired file and find the $DATA attribute we are looking for.
    let file = parse_file_arg(file_name, info)?;
    let data_item = match file.data(&mut info.fs, data_stream_name) {
        Some(data_item) => data_item,
        None => {
            println!("The file does not have a \"{data_stream_name}\" $DATA attribute.");
            return Ok(());
        }
    };
    let data_item = data_item?;
    let data_attribute = data_item.to_attribute()?;
    let mut data_value = data_attribute.value(&mut info.fs)?;

    println!(
        "Saving {} bytes of data in \"{}\"...",
        data_value.len(),
        output_file_name
    );
    let mut buf = [0u8; 4096];

    loop {
        let bytes_read = data_value.read(&mut info.fs, &mut buf)?;
        if bytes_read == 0 {
            break;
        }

        output_file.write_all(&buf[..bytes_read])?;
    }

    Ok(())
}

fn help(arg: &str) -> Result<()> {
    match arg {
        "attr" => {
            println!("Usage: attr FILE");
            println!();
            println!("Shows the structure of all NTFS attributes of a single file, not including their data runs.");
            println!("Try \"attr_runs\" if you are also interested in Data Run information.");
            help_file("attr");
        }
        "attr_runs" => {
            println!("Usage: attr_runs FILE");
            println!();
            println!("Shows the structure of all NTFS attributes of a single file, including their data runs.");
            println!("Try \"attr\" if you don't need the Data Run information.");
            help_file("attr_runs");
        }
        "cd" => {
            println!("Usage: cd SUBDIRECTORY");
            println!();
            println!("Changes the current directory to SUBDIRECTORY.");
            println!("This implementation of \"cd\" only supports subdirectories of the current directory.");
            println!("\"cd ..\" moves back into the parent directory.");
        }
        "dir" => {
            println!("Usage: dir");
            println!();
            println!("Lists filenames in the current directory (like \"ls\" on UNIX systems).");
            println!("No additional parameters are supported.");
            println!("Try \"fileinfo\" to get additional information about a single file.");
        }
        "fileinfo" => {
            println!("Usage: fileinfo FILE");
            println!();
            println!("Shows information about a single file (by parsing its NTFS attributes).");
            help_file("fileinfo");
        }
        "get" => {
            println!("Usage:");
            println!("  get FILE");
            println!("  get FILE:STREAM");
            println!();
            println!("Copies the data of a single file from the NTFS filesystem to the current directory of your local filesystem.");
            println!("Optionally, you can append a colon and a data stream name to copy a specific data stream of that file.");
            println!();
            println!("This command will fail if the file already exists in the current directory.");
            help_file("get");
        }
        _ => {
            println!("Available Commands:");
            println!("  attr      - Show structure of NTFS attributes of a particular file");
            println!("  attr_runs - Show structure of NTFS attributes of a particular file, including data runs");
            println!("  cd        - Change the current directory");
            println!("  dir       - Show files of the current directory");
            println!("  exit      - Quit ntfs-shell");
            println!("  fileinfo  - Show information about a particular file");
            println!("  fsinfo    - Show general filesystem information");
            println!("  get       - Copy a file from the NTFS filesystem");
            println!("  help      - Show this help");
            println!("  quit      - Quit ntfs-shell");
            println!();
            println!(
                "You can also enter \"help COMMAND\" to get additional help about some commands."
            );
        }
    }

    Ok(())
}

fn help_file(command: &str) {
    println!();
    println!("FILE can have one of the following formats:");
    println!("  ● A name of a file in the current directory.");
    println!("    Enter the filename as is, including any spaces. Don't put it into additional quotation marks.");
    println!("    Examples:");
    println!("      ○ {command} ntoskrnl.exe");
    println!("      ○ {command} File with spaces.exe");
    println!("  ● A File Record Number anywhere on the filesystem.");
    println!("    This is indicated through a leading slash (/). A hexadecimal File Record Number is indicated via 0x.");
    println!("    Examples:");
    println!("      ○ {command} /5");
    println!("      ○ {command} /0xa299");
}

#[allow(clippy::from_str_radix_10)]
fn parse_file_arg<'n, T>(arg: &str, info: &mut CommandInfo<'n, T>) -> Result<NtfsFile<'n>>
where
    T: Read + Seek,
{
    if arg.is_empty() {
        bail!("Missing argument!");
    }

    if let Some(record_number_arg) = arg.strip_prefix('/') {
        let record_number = match record_number_arg.strip_prefix("0x") {
            Some(hex_record_number_arg) => u64::from_str_radix(hex_record_number_arg, 16),
            None => u64::from_str_radix(record_number_arg, 10),
        };

        if let Ok(record_number) = record_number {
            let file = info.ntfs.file(&mut info.fs, record_number)?;
            Ok(file)
        } else {
            bail!(
                "Cannot parse record number argument \"{}\"",
                record_number_arg
            )
        }
    } else {
        let index = info
            .current_directory
            .last()
            .unwrap()
            .directory_index(&mut info.fs)?;
        let mut finder = index.finder();

        if let Some(entry) = NtfsFileNameIndex::find(&mut finder, info.ntfs, &mut info.fs, arg) {
            let entry = entry?;
            let file = entry.to_file(info.ntfs, &mut info.fs)?;
            Ok(file)
        } else {
            bail!("No such file or directory \"{}\".", arg)
        }
    }
}
