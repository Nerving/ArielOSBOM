mod common;

use std::env;

use arielosbom::{
    generate_raw_sbom,
    sbom::{cyclonedx_v16::CycloneDxSbomV1_6, cyclonedx_v17::CycloneDxSbomV1_7},
};

use common::{
    STANDARD_BUILDER, STANDARD_EXAMPLE, generate_build_command_locked,
    generate_example_build_context,
};

// to be removed later when stuff is handled with some config or whatever to determine whether testing is happening
fn set_test_env() {
    unsafe {
        env::set_var("TESTING", "1");
    }
}

#[test]
fn deterministic_generation_raw() {
    common::check_environment();

    set_test_env();

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    generate_build_command_locked(&mut context);

    let sbom1 = generate_raw_sbom(&mut context, &None, false).unwrap().sbom;

    let sbom2 = generate_raw_sbom(&mut context, &None, false).unwrap().sbom;

    assert_eq!(sbom1, sbom2);
}

#[test]
fn deterministic_generation_cdx16() {
    common::check_environment();

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    generate_build_command_locked(&mut context);

    let mut sbom1 =
        CycloneDxSbomV1_6::from_raw(&generate_raw_sbom(&mut context, &None, false).unwrap().sbom);
    sbom1.default_uuid();

    let mut sbom2 =
        CycloneDxSbomV1_6::from_raw(&generate_raw_sbom(&mut context, &None, false).unwrap().sbom);
    sbom2.default_uuid();

    assert_eq!(sbom1, sbom2);
}

#[test]
fn deterministic_generation_cdx17() {
    common::check_environment();

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    generate_build_command_locked(&mut context);

    let mut sbom1 =
        CycloneDxSbomV1_7::from_raw(&generate_raw_sbom(&mut context, &None, false).unwrap().sbom);
    sbom1.default_uuid();

    let mut sbom2 =
        CycloneDxSbomV1_7::from_raw(&generate_raw_sbom(&mut context, &None, false).unwrap().sbom);
    sbom2.default_uuid();

    assert_eq!(sbom1, sbom2);
}
