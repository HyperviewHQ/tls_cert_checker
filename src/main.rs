use std::{
    fs::File,
    io::{self, BufRead},
    process,
};

use anyhow::Result;
use clap::Parser;
use csv::Writer;
use log::{error, info, warn};
use tls_cert_checker::{get_cert_info, CertInfo};

#[derive(Parser, Debug)]
#[clap(author="Hyperview Inc.", version, about="A simple remote TLS certificate information fetcher", long_about = None)]
struct Args {
    /// Input filename.
    /// One domain or hostname per line.
    #[clap(short, long, value_parser)]
    input_filename: String,

    /// Output CSV file
    #[clap(short, long, value_parser)]
    output_filename: String,
}

fn main() -> Result<()> {
    // Initialize the logging engine
    env_logger::init();

    let args = Args::parse();

    println!("{:?}", args);

    let data_lines = match File::open(args.input_filename) {
        Ok(file) => io::BufReader::new(file).lines(),
        Err(e) => {
            error!("Error opening input file: {}", e);
            process::exit(1);
        }
    };

    let mut hostnames: Vec<String> = Vec::new();

    for line in data_lines {
        if let Ok(x) = line {
            let entry = x.trim().to_string();
            if entry.len() > 3 {
                info!("hostname {} read from input", entry);
                hostnames.push(entry);
            } else {
                warn!("potentially malformed hostname: {}", entry);
            }
        }
    }

    let mut cert_info: Vec<CertInfo> = Vec::new();

    hostnames.into_iter().for_each(|h| {
        match get_cert_info(h.clone()) {
            Ok(x) => {
                info!("info for: {}, {:?}", h, x);
                cert_info.push(x);
            }
            Err(e) => {
                error!("hostname: {}, {}", h, e)
            }
        };
    });

    match write_output(args.output_filename, cert_info) {
        Ok(()) => {
            info!("hostname certificate data written to output");
        },
        Err(e) => {
            error!("error writing data to output file: {}", e);
        }
    };

    Ok(())
}

fn write_output(output_filename: String, cert_info: Vec<CertInfo>) -> Result<()> {
    let mut writer = Writer::from_path(output_filename)?;

    for c in cert_info {
        writer.serialize(c)?;
    }

    writer.flush()?;

    Ok(())
}
