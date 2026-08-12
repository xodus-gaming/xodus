use std::path::Path;
use std::process::ExitCode;

use msixvc::xvc2::Msixvc2File;

pub fn info(path: String) -> ExitCode {
    println!("Opening MSIXVC2 package: {path}");
    match Msixvc2File::open_path(&path) {
        Ok(pkg) => {
            let p = pkg.package();
            println!("MSIXVC2 Package Information:");
            println!("  Content ID:            {}", p.content_id);
            println!("  Fulfillment Content ID: {}", p.fulfillment_content_id);
            println!("  Product ID:            {}", p.product_id);
            println!("  Store ID:              {}", p.store_id);
            println!("  Version:               {:?}", p.version);
            println!("  Supported Platforms:   {:?}", p.supported_platforms);
            println!("  Chunks:                {}", p.chunks.len());
            println!("  Boxes:                 {}", p.boxes.len());
            println!("  Encrypted Keys:        {}", p.keys.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to open MSIXVC2 package: {e}");
            ExitCode::FAILURE
        }
    }
}

pub fn extract(path: String, output: String, content_key_hex: Option<String>) -> ExitCode {
    println!("Extracting MSIXVC2 package: {path} -> {output}");

    let mut msixvc2 = match Msixvc2File::open_path(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open MSIXVC2 package: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(hex_str) = content_key_hex {
        match hex::decode(hex_str.trim()) {
            Ok(key_bytes) => {
                msixvc2.submit_keys(Some(key_bytes), None);
            }
            Err(e) => {
                eprintln!("Invalid content key hex string: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    println!("Decrypting file names...");
    if let Err(e) = msixvc2.load_file_names() {
        eprintln!("Failed to load file names: {e}");
        return ExitCode::FAILURE;
    }

    println!("Extracting {} files...", msixvc2.files().len());
    if let Err(e) = msixvc2.extract_files(Path::new(&output)) {
        eprintln!("Extraction failed: {e}");
        return ExitCode::FAILURE;
    }

    println!("Successfully extracted MSIXVC2 package to {output}");
    ExitCode::SUCCESS
}
