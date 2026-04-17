use std::{
    fs::{File}, 
    path::{Path}, 
};

use serde_json::{Value};

mod common;
use common::CONSTPATHS as PATHS;
use common::assert_sbom_generation_status;

const COAP_EXAMPLE_PATH: &str = "examples/coap-client";

const OUTPUT_NAME_1: &str = "deterministic-1";
const OUTPUT_NAME_2: &str = "deterministic-2";

#[test]
fn deterministic_generation_raw() {

    common::check_environment();

    let output = common::generate_test_sbom(
        Some(vec![("TESTING","1")]),
        Path::new(PATHS.ariel_os), 
        &vec!["raw"], 
        Some(vec!["nrf52840dk"]), 
        OUTPUT_NAME_1, 
        Path::new(COAP_EXAMPLE_PATH).join("Cargo.toml"), 
        None, 
        Path::new(".")
    ).expect("arielosbom execution failed");

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.raw.json")).exists(), "failed to find first generated raw SBOM file");

    let _ = common::generate_test_sbom(
        Some(vec![("TESTING","1")]),
        Path::new(PATHS.ariel_os), 
        &vec!["raw"], 
        Some(vec!["nrf52840dk"]), 
        OUTPUT_NAME_2, 
        Path::new(COAP_EXAMPLE_PATH).join("Cargo.toml"), 
        None, 
        Path::new(".")
    ).expect("arielosbom execution failed");

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_2, "_nrf52840dk.raw.json")).exists(), "failed to find second generated raw SBOM file");

    let raw_1_file = File::open(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.raw.json")))
        .expect("failed to open first raw SBOM");
    let raw_1_data: Value = serde_json::from_reader(raw_1_file)
        .expect("failed to parse first raw SBOM");

    let raw_2_file = File::open(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.raw.json")))
        .expect("failed to open second raw SBOM");
    let raw_2_data: Value = serde_json::from_reader(raw_2_file)
        .expect("failed to parse second raw SBOM");
    
    assert_eq!(raw_1_data, raw_2_data);

}

#[test]
fn deterministic_generation_cdx16() {

    common::check_environment();

    let output = common::generate_test_sbom(
        Some(vec![("TESTING","1")]),
        Path::new(PATHS.ariel_os), 
        &vec!["cdx_1.6"], 
        Some(vec!["nrf52840dk"]), 
        OUTPUT_NAME_1, 
        Path::new(COAP_EXAMPLE_PATH).join("Cargo.toml"), 
        None, 
        Path::new(".")
    ).expect("arielosbom execution failed");

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.1-6.cdx.json")).exists(), "failed to find first generated CycloneDx 1.6 SBOM file");

    let _ = common::generate_test_sbom(
        Some(vec![("TESTING","1")]),
        Path::new(PATHS.ariel_os), 
        &vec!["cdx_1.6"], 
        Some(vec!["nrf52840dk"]), 
        OUTPUT_NAME_2, 
        Path::new(COAP_EXAMPLE_PATH).join("Cargo.toml"), 
        None, 
        Path::new(".")
    ).expect("arielosbom execution failed");

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_2, "_nrf52840dk.1-6.cdx.json")).exists(), "failed to find second generated CycloneDx 1.6 SBOM file");

    let cdx16_1_file = File::open(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.1-6.cdx.json")))
        .expect("failed to open first CycloneDx 1.6 SBOM");
    let cdx16_1_data: Value = serde_json::from_reader(cdx16_1_file)
        .expect("failed to parse first CycloneDx 1.6 SBOM");

    let cdx16_2_file = File::open(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_2, "_nrf52840dk.1-6.cdx.json")))
        .expect("failed to open second CycloneDx 1.6 SBOM");
    let cdx16_2_data: Value = serde_json::from_reader(cdx16_2_file)
        .expect("failed to parse second CycloneDx 1.6 SBOM");
    
    assert_eq!(cdx16_1_data, cdx16_2_data);

}

#[test]
fn deterministic_generation_cdx17() {

    common::check_environment();

    let output = common::generate_test_sbom(
        Some(vec![("TESTING","1")]),
        Path::new(PATHS.ariel_os), 
        &vec!["cdx_1.7"], 
        Some(vec!["nrf52840dk"]), 
        OUTPUT_NAME_1, 
        Path::new(COAP_EXAMPLE_PATH).join("Cargo.toml"), 
        None, 
        Path::new(".")
    ).expect("arielosbom execution failed");

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.1-7.cdx.json")).exists(), "failed to find first generated CycloneDx SBOM 1.7 file");

    let _ = common::generate_test_sbom(
        Some(vec![("TESTING","1")]),
        Path::new(PATHS.ariel_os), 
        &vec!["cdx_1.7"], 
        Some(vec!["nrf52840dk"]), 
        OUTPUT_NAME_2, 
        Path::new(COAP_EXAMPLE_PATH).join("Cargo.toml"), 
        None, 
        Path::new(".")
    ).expect("arielosbom execution failed");

    assert!(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_2, "_nrf52840dk.1-7.cdx.json")).exists(), "failed to find second generated CycloneDx 1.7 SBOM file");

    let cdx17_1_file = File::open(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_1, "_nrf52840dk.1-7.cdx.json")))
        .expect("failed to open first CycloneDx 1.7 SBOM");
    let cdx17_1_data: Value = serde_json::from_reader(cdx17_1_file)
        .expect("failed to parse first CycloneDx 1.7 SBOM");

    let cdx17_2_file = File::open(Path::new(PATHS.output).join(format!("{}{}", OUTPUT_NAME_2, "_nrf52840dk.1-7.cdx.json")))
        .expect("failed to open second CycloneDx 1.7 SBOM");
    let cdx17_2_data: Value = serde_json::from_reader(cdx17_2_file)
        .expect("failed to parse second CycloneDx 1.7 SBOM");
    
    assert_eq!(cdx17_1_data, cdx17_2_data);

}