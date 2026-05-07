use std::{
    fs::create_dir,
    path::{Path, PathBuf},
};

use clap::Parser;

use arielosbom::{
    ArielOsBuildContext,
    sbom::{write_sbom_to_file, BomFormat, CycloneDxSpecVersion}
};


const FIXTURE_OOT_PATH: &'static str = "tests/fixtures/out-of-tree-coap-client";
const OUTPUT_DIR: &'static str = "output";

#[derive(Debug, Parser)]
pub struct Args {

    #[arg(
        id = "project_root_path",
        value_name = "PATH",  
        short = 'r', 
        long = "root-path",
        required = true,
        help = "Path to project root",
    )]
    pub project_root_path: PathBuf,

    #[arg(
        id = "builder",
        value_name = "BUILDER",
        default_value = "nrf52840dk",
        short = 'b',
        long = "builder",
        required = false,
        help = "Laze builder target to generate the SBOM for; if not provided, uses nrf52840dk",
        //long_help = ""
    )]
    pub builder: String,

}

fn main() {

    let input = Args::parse(); 

    if !(Path::new(&input.project_root_path).exists()) { panic!("Cannot find the Ariel OS project at {:?}", input.project_root_path); }

    if !(Path::new(OUTPUT_DIR).exists()) {
        match create_dir(&OUTPUT_DIR) {
            Ok(_) => println!("created output directory: {}\n", Path::new(".").join(OUTPUT_DIR).display()),
            Err(e) => panic!("failed to created output directory: {:?}\n", e)
        };
    }

    let import_path = if input.project_root_path == PathBuf::from(FIXTURE_OOT_PATH) {Path::new("../ariel-os")} else {Path::new("build/imports/ariel-os")};
    
    let mut build_context = ArielOsBuildContext::from_paths(
        &PathBuf::from(input.project_root_path),
        &PathBuf::from("Cargo.toml"),
        &PathBuf::from("Cargo.lock"),
        &import_path.to_path_buf(),
        &input.builder
    );

    let mut raw_sbom = arielosbom::generate_raw_sbom(&mut build_context);

    write_sbom_to_file(&mut raw_sbom, &BomFormat::CDX(CycloneDxSpecVersion::V1_6), "custom-oot-example", Path::new(OUTPUT_DIR), build_context.builder());
        
}
