use std::{
    fs::create_dir,
    path::{Path, PathBuf},
};

use arielosbom::{
    ArielOsBuildContext,
    sbom::{write_sbom_to_file, BomFormat, CycloneDxSpecVersion}
};


const ARIEL_OS_ROOT_PATH: &'static str = "tests/fixtures/ariel-os";
const EXAMPLE_SUB_PATH: &'static str = "examples/coap-client";
const OUTPUT_DIR: &'static str = "output";


fn main() {

    if !(Path::new(ARIEL_OS_ROOT_PATH).exists()) { panic!("Cannot find the Ariel OS project at {:?}", ARIEL_OS_ROOT_PATH); }

    if !(Path::new(OUTPUT_DIR).exists()) {
        match create_dir(&OUTPUT_DIR) {
            Ok(_) => println!("created output directory: {}\n", Path::new(".").join(OUTPUT_DIR).display()),
            Err(e) => panic!("failed to created output directory: {:?}\n", e)
        };
    }
        
    let mut build_context = ArielOsBuildContext::from_paths(
        &PathBuf::from(ARIEL_OS_ROOT_PATH),
        &Path::new(EXAMPLE_SUB_PATH).join("Cargo.toml"),
        &PathBuf::from("Cargo.lock"),
        &PathBuf::from("."),
        &"nrf52840dk".to_string()
    );

    let mut raw_sbom = arielosbom::generate_raw_sbom(&mut build_context);

    write_sbom_to_file(&mut raw_sbom, &BomFormat::CDX(CycloneDxSpecVersion::V1_6), "ariel-os-example", Path::new(OUTPUT_DIR), build_context.builder());
        
}
