use clap::{Arg, Command};
use std::path::Path;

mod hef;
use hef::Hef;

fn main() {
    // Define the CLI arguments using clap 4.x
    let matches = Command::new("HEF CLI")
        .version("1.0")
        .author("Your Name <your_email@example.com>")
        .about("Parses HEF files and prints metadata in JSON format")
        .arg(
            Arg::new("hef_file")
                .help("Path to the HEF file to parse")
                .required(true),
        )
        .get_matches();

    // Get the HEF file path from arguments
    let hef_file = matches.get_one::<String>("hef_file").expect("Argument is required");

    // Ensure the file exists
    if !Path::new(hef_file).exists() {
        eprintln!("Error: File does not exist: {}", hef_file);
        std::process::exit(1);
    }

    Hef::extract_proto(hef_file, "proto_dump.pb.cc").expect("Could not extract proto");

    // Parse the HEF file
    match Hef::parse(hef_file) {
        Ok(hef) => {
            // Use Hef's to_json method to serialize the object
            match hef.to_json() {
                Ok(json) => println!("{}", json),
                Err(e) => eprintln!("Error serializing HEF metadata to JSON: {}", e),
            }
        }
        Err(e) => {
            eprintln!("Error parsing HEF file: {}", e);
            std::process::exit(1);
        }
    }
}
