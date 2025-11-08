// TODO:
// target selection
// multiple formats; multiple output names? match output name, BOM and file format in order?
// include build deps yes/no, other irrelevant(?) deps yes/no?
// log yes/no?
// URI of where the SBOM will be accessible?

use crate::sbom::{BomFormat, FileFormat};

use clap::{Parser};

use std::{
    fmt::{Formatter},
    path::{PathBuf},
    str::{FromStr},
};



#[derive(Debug, Parser)]
pub struct Args {

    #[arg(
        id = "project_root_path",
        value_name = "PATH", 
        default_value = "./", 
        short = 'r', 
        long = "root-path",
        required = false,
    )]
    pub project_root_path: PathBuf,

    //remove?
    #[arg(
        id = "project_manifest_path",
        value_name = "PATH",
        default_value = "./Cargo.toml",
        short = 'm',
        long = "manifest-path",
        required = false,
    )]
    pub project_manifest_path: PathBuf,

    //remove?
    #[arg(
        id = "project_lock_path",
        value_name = "PATH",
        default_value = "./Cargo.lock",
        short = 'l',
        long = "lock-path",
        required = false,
    )]
    pub project_lock_path: PathBuf,

    #[arg(
        id = "BOM_formats",
        value_name = "BOM_FORMAT",
        num_args = 1..3,    // for future if to generate in multiple formats
        default_value = "Raw",
        short = 'b',
        long = "bom-formats",
        required = false,
    )]
    pub bom_formats: Vec<BomFormat>,

    #[arg (
        id = "file_format",
        value_name = "FILE_EXTENSION",
        default_value = "json",
        short = 'f',
        long = "file-format",
        required = false
    )]
    pub file_format: FileFormat, // potentially Vec later if needed, same as BOM_formats

    #[arg(
        id = "output_name",
        value_name = "FILE_NAME",
        default_value = "arielosbom",
        short = 'o',
        long = "output-name",
        required = false
    )]
    pub output_name: String,    // again potentially Vec if multiple in future

    #[arg(
        id = "bloat_filter",
        value_name = "BOOL",
        default_value = "true",
        //short = 'b',
        long = "bloat-filter",
        required = false
    )]
    pub bloat_filter: bool,
}

// impls for clap parsing

impl FromStr for BomFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "raw" => Ok(BomFormat::Raw),
            "spdx" => Ok(BomFormat::SPDX),
            "cdx" | "cyclonedx" | "cyclone-dx" => Ok(BomFormat::CDX),
            other => Err(format!("Invalid or unsupported BOM format: {}", other))
        }
    }
}

impl FromStr for FileFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "json" => Ok(FileFormat::Json),
            other => Err(format!("Invalid or unsupported file format: {}", other))
        }
    }
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", match self {
            FileFormat::Json => "json",
        })
    }
}