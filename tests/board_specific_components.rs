// TODO: look at more concrete examples with additional crates on boards?; also check if any other board families/specific singular boards
// do all checks on minimal for baseline components?

mod common;

use arielosbom::{
    generate_raw_sbom,
};

use common::{
    generate_example_build_context,
    STANDARD_BUILDER,
    STANDARD_EXAMPLE,
};

#[test]
fn esp_specific_components() {

    common::check_environment();

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, "espressif-esp32-c6-devkitc-1");
    let sbom = generate_raw_sbom(&mut context);

    // these should be guaranteed to appear; others exist, but aren't necessarily present for every example
        // would need more elaborate testing, e. g. of more examples, if wanting to check for those too
    let esp_list = vec![
        "ariel-os-esp", "esp-alloc", "esp-bootloader-esp-idf", "esp-config", "esp-hal", "esp-hal-procmacros", "esp-metadata-generated", 
        "esp-println", "esp-riscv-rt", "esp-rom-sys", "esp-sync"
        ];
    
    for entry in esp_list {
        assert!(sbom.components.iter().any(|component| component.name == entry), "missing component: {}", entry);
    }
    
}

#[test]
fn nrf_specific_components() {

    common::check_environment();

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    let sbom = generate_raw_sbom(&mut context);

    // these should be guaranteed to appear; others exist, but aren't necessarily present for every example
        // would need more elaborate testing, e. g. of more examples, if wanting to check for those too
    let nrf_list = vec!["ariel-os-nrf", "embassy-nrf", "nrf-pac"];
    
    for entry in nrf_list {
        assert!(sbom.components.iter().any(|component| component.name == entry), "missing component: {}", entry);
    }
    
}

#[test]
fn rp_specific_components() {

    common::check_environment();

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, "rpi-pico");
    let sbom = generate_raw_sbom(&mut context);

    // these should be guaranteed to appear; others exist, but aren't necessarily present for every example
        // would need more elaborate testing, e. g. of more examples, if wanting to check for those too
    let rp_list = vec!["ariel-os-rp", "embassy-rp", "rp-pac", "rp2040-boot2"];
    
    for entry in rp_list {
        assert!(sbom.components.iter().any(|component| component.name == entry), "missing component: {}", entry);
    }
    
}

#[test]
fn stm32_specific_components() {

    common::check_environment();

    let mut context = generate_example_build_context("thermometer", "stm32u083c-dk");
    let sbom = generate_raw_sbom(&mut context);

    // these should be guaranteed to appear; others exist, but aren't necessarily present for every example
        // would need more elaborate testing, e. g. of more examples, if wanting to check for those too
    let stm_list = vec!["ariel-os-stm32", "ariel-os-stm32-mapping", "embassy-stm32", "stm32-fmc", "stm32-metapac"];
    
    for entry in stm_list {
        assert!(sbom.components.iter().any(|component| component.name == entry), "missing component: {}", entry);
    }
    
}