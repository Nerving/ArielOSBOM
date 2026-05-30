use arielosbom::sbom::{BomFormat, FileFormat};

use clap::Parser;

use std::path::PathBuf;

#[derive(Debug, Parser)]
pub struct Args {
    #[arg(
        id = "project_root_path",
        value_name = "PATH",
        default_value = "./",
        short = 'r',
        long = "root-path",
        required = true,
        help = "Path to project root"
    )]
    pub project_root_path: PathBuf,

    #[arg(
        id = "BOM_formats",
        value_name = "BOM_FORMAT",
        num_args = 1..4,    // can be more in future
        default_value = "cdx_1.6",
        short = 'b',
        long = "bom-formats",
        required = false,
        help = "BOM formats to generate (space-separated)",
        long_help = "BOM formats to generate (space-separated)\nPossible values (case-insensitive):\n\t- raw:\t\t\t\toutput of the raw aggregated information\n\t- spdx:\t\t\t\tno SPDX support currently\n\t- cdx_1.6/cyclonedx_1.6:\tCycloneDX version 1.6\n\t- cdx_1.7/cyclonedx_1.7:\tCycloneDX version 1.7"
    )]
    pub bom_formats: Vec<BomFormat>,

    #[arg(
        id = "file_format",
        value_name = "FILE_EXTENSION",
        default_value = "json",
        short = 'f',
        long = "file-format",
        required = false,
        help = "File format of the generated SBOM",
        long_help = "File format of the generated SBOM\nPossible values (case-insensitive):\n\t-json"
    )]
    pub file_format: FileFormat, // potentially Vec later if needed, same as BOM_formats

    #[arg(
        id = "builders",
        value_name = "BUILDERS",
        num_args = 0..16,
        default_value = "none",
        //short = 'b',
        long = "builders",
        required = false,
        help = "Laze builder targets (max 16, space separated) to generate SBOMs for; if not provided, uses last build command",
        //long_help = ""
    )]
    pub builders: Vec<String>,

    #[arg(
        id = "output_name",
        value_name = "FILE_NAME",
        default_value = "arielosbom",
        short = 'o',
        long = "output-name",
        required = false,
        help = "File name of the generated SBOM(s)",
        long_help = "File name of the generated SBOM(s)\nDepending on the chosen SBOM format, the full file name will be <FILE_NAME>_<BUILDER>.<BOM_FORMAT>.<FILE_EXTENSION>"
    )]
    pub output_name: String, // again potentially Vec if multiple in future

    #[arg(
        id = "output_directory",
        value_name = "PATH",
        default_value = "./output",
        long = "output-directory",
        required = false,
        help = "Path to where the generated SBOMs are to be stored (relative to execution path or absolute)"
    )]
    pub output_dir: PathBuf,

    #[arg(
        id = "project_manifest_path",
        value_name = "PATH",
        default_value = "./Cargo.toml",
        short = 'm',
        long = "manifest-path",
        required = false,
        help = "Path to the build's manifest file relative to its root"
    )]
    pub project_manifest_path: PathBuf,

    #[arg(
        id = "project_lock_path",
        value_name = "PATH",
        default_value = "./Cargo.lock",
        short = 'l',
        long = "lock-path",
        required = false,
        help = "Path to the project's lock file relative to its root"
    )]
    pub project_lock_path: PathBuf,

    #[arg(
        id = "arielos_import_path",
        value_name = "PATH",
        default_value = "./build/imports/ariel-os/",
        short = 'i',
        long = "import-path",
        required = false,
        help = "Path to the project's ArielOS import directory relative to its root"
    )]
    pub arielos_import_path: PathBuf,

    #[arg(
        id = "emit_cargo_artifacts",
        long = "emit-cargo-artifacts",
        help = "Determines whether cargo tree and cargo metadata are also written to the output directory",
        long_help = "Determines whether cargo tree and cargo metadata are also written to the output directory; the full file names will be <FILE_NAME>_<BUILDER>.metadata/tree.json/txt"
    )]
    pub emit_cargo_artifacts: bool,
}
