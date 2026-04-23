mod common;

use std::{
    env,
    path::{Path, PathBuf}
};

use arielosbom::{
    ArielOsBuildContext, 
    generate_raw_sbom,
    sbom::{cyclonedx_v16::CycloneDxSbomV1_6, cyclonedx_v17::CycloneDxSbomV1_7},
};

use common::{
    check_environment,
    CONSTPATHS as PATHS,
};


fn generate_build_context() -> ArielOsBuildContext {
    
    set_test_env();
    
    ArielOsBuildContext::from_paths(
        &PathBuf::from(PATHS.ariel_os), 
        &Path::new("examples").join("coap-client").join("Cargo.toml"), 
        &PathBuf::from("Cargo.lock"), 
        &PathBuf::from("."), 
        &"nrf52840dk".to_string())
}

// to be removed later when stuff is handled with some config or whatever to determine whether testing is happening
fn set_test_env() {
    unsafe {
        env::set_var("TESTING", "1");
    }
}

#[test]
fn deterministic_generation_raw() {

    common::check_environment();

    let mut context = generate_build_context();

    let sbom1 = generate_raw_sbom(&mut context);

    let sbom2 = generate_raw_sbom(&mut context);
    
    assert_eq!(sbom1, sbom2);

}

#[test]
fn deterministic_generation_cdx16() {

    check_environment();

    let mut context = generate_build_context();

    let mut sbom1 = CycloneDxSbomV1_6::from_raw(&generate_raw_sbom(&mut context));

    let mut sbom2 = CycloneDxSbomV1_6::from_raw(&generate_raw_sbom(&mut context));
    
    assert_eq!(sbom1.default_uuid(), sbom2.default_uuid());

}

#[test]
fn deterministic_generation_cdx17() {

    common::check_environment();

    let mut context = generate_build_context();

    let mut sbom1 = CycloneDxSbomV1_7::from_raw(&generate_raw_sbom(&mut context));

    let mut sbom2 = CycloneDxSbomV1_7::from_raw(&generate_raw_sbom(&mut context));
    
    assert_eq!(sbom1.default_uuid(), sbom2.default_uuid());

}