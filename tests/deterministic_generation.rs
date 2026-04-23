mod common;

use std::{
    io::Error,
    path::{Path},
    process::Output, 
};

use common::{
    *,
    CONSTPATHS as PATHS,
};


const COAP_EXAMPLE_PATH: &str = "examples/coap-client";
const OUTPUT_NAME_1: &str = "deterministic-1";
const OUTPUT_NAME_2: &str = "deterministic-2";

fn generate_sbom(format: &str, output_name: &str) -> Result<Output, Error> {
    
    test_binary(
        Some(create_deterministic_envs()),
        Path::new(PATHS.ariel_os), 
        &vec![format], 
        Some(vec!["nrf52840dk"]), 
        output_name, 
        Some(&Path::new(COAP_EXAMPLE_PATH).join("Cargo.toml")), 
        None, 
        Some(Path::new("."))
    )
}

#[test]
fn deterministic_generation_raw() {

    common::check_environment();

    let output = generate_sbom("raw", OUTPUT_NAME_1);

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.raw.json")).exists(), "failed to find first generated raw SBOM file");

    let output = generate_sbom("raw", OUTPUT_NAME_2);

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_2, "_nrf52840dk.raw.json")).exists(), "failed to find second generated raw SBOM file");

    let raw_1_data = parse_sbom(
        &Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.raw.json")), 
        "first raw"
    );

    let raw_2_data = parse_sbom(
        &Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.raw.json")), 
        "second raw"
    );
    
    assert_eq!(raw_1_data, raw_2_data);

}

#[test]
fn deterministic_generation_cdx16() {

    check_environment();

    let output = generate_sbom("cdx_1.6", OUTPUT_NAME_1);

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.1-6.cdx.json")).exists(), "failed to find first generated CycloneDx 1.6 SBOM file");

    let output = generate_sbom("cdx_1.6", OUTPUT_NAME_2);

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_2, "_nrf52840dk.1-6.cdx.json")).exists(), "failed to find second generated CycloneDx 1.6 SBOM file");

    let cdx16_1_data = parse_sbom(
        &Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.1-6.cdx.json")), 
        "first CycloneDx 1.6"
    );

    let cdx16_2_data = parse_sbom(
        &Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_2, "_nrf52840dk.1-6.cdx.json")), 
        "first CycloneDx 1.6"
    );
    
    assert_eq!(cdx16_1_data, cdx16_2_data);

}

#[test]
fn deterministic_generation_cdx17() {

    common::check_environment();

    let output = generate_sbom("cdx_1.7", OUTPUT_NAME_1);

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.1-7.cdx.json")).exists(), "failed to find first generated CycloneDx SBOM 1.7 file");

    let output = generate_sbom("cdx_1.7", OUTPUT_NAME_2);

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_2, "_nrf52840dk.1-7.cdx.json")).exists(), "failed to find second generated CycloneDx 1.7 SBOM file");

    let cdx17_1_data = parse_sbom(
        &Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.1-7.cdx.json")), 
        "first CycloneDx 1.7"
    );

    let cdx17_2_data = parse_sbom(
        &Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_2, "_nrf52840dk.1-7.cdx.json")), 
        "first CycloneDx"
    );

    assert_eq!(cdx17_1_data, cdx17_2_data);

}