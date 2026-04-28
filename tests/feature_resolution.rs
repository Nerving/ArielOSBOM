mod common;

use std::{
    collections::HashSet, 
    path::Path, 
    process::Command,
};

use arielosbom::{
    tree::generate_cargo_tree_data,
};

use common::{
    check_environment,
    CONSTPATHS as PATHS,
    generate_example_build_context,
    STANDARD_BUILDER,
    STANDARD_EXAMPLE,
};

const BUILD_COMMAND_FIXTURE_PATH: &'static str = "tests/fixtures/feature_resolution/";
const FIXED_ENVS: &[(&'static str, &'static str)] = &[
    ("OPENOCD_ARGS","\"-f board/nordic_nrf52_dk.cfg\""),
    ("SCRIPTS","./scripts"),
    ("CONFIG_BOARD","nrf52840dk"),
    ("CARGO_BUILD_TARGET","thumbv7em-none-eabihf"),
    ("CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUNNER","'probe-rs run --protocol=swd --chip nrf52840_xxAA --preverify'"),
    ("CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUSTFLAGS","--cfg context=\"nrf52840dk\" --cfg context=\"nrf52840\" --cfg context=\"nrf52\" --cfg context=\"nrf\" --cfg context=\"ariel-os\" --cfg context=\"default\" --cfg getrandom_backend=\"custom\" --cfg stable -Cembed-bitcode=yes -Clto=fat -Ccodegen-units=1 --cfg capability=\"hw/device-identity\" -Clink-arg=-Tdefmt.x --cfg armv7m --cfg armv7m_eabihf -Clink-arg=--nmagic -Clink-arg=--no-eh-frame-hdr -Clink-arg=-Tlinkme.x -Clink-arg=-Tlink.x -Clink-arg=-Teheap.x -Clink-arg=-Tdevice.x -Clink-arg=-Tisr_stack.x --cfg context=\"cortex-m\" --cfg context=\"cortex-m4f\" --cfg capability=\"hw/usb-device-port\""),
    ("CARGO_TARGET_DIR","./build/bin/nrf52840dk/cargo"),
    ("CONFIG_EXECUTOR_STACKSIZE","32768"),
    ("CONFIG_ISR_STACKSIZE","2048"),
    ("CC","\"\""),
    ("CFLAGS","\"\""),
    ("DEFMT_LOG","info,"),   
];
const FIXED_FEATURES: &'static str = "--features=ariel-os/liboscore-provide-abort,ariel-os/liboscore-provide-assert,ariel-os/hwrng,ariel-os/random,ariel-os/dhcpv4,ariel-os/ipv4,ariel-os/semihosting,ariel-os/single-core,ariel-os/executor-interrupt,ariel-os/defmt-rtt,ariel-os/panic-printing,ariel-os/defmt,ariel-os/debug-console,ariel-os/usb,ariel-os/usb-ethernet,ariel-os/coap-transport-udp,ariel-os/coap,";
const FIXED_MANIFEST_PATH: &'static str = "examples/coap-client/Cargo.toml";

fn generate_fixed_feature_list() -> Vec<&'static str> {
    FIXED_FEATURES.split_once("=").unwrap().1.split_inclusive(",").collect()
}

fn parse_fixed_tree_data(command_output: Vec<u8>) -> HashSet<String> {

    let tree_data = match String::from_utf8(command_output) {
        Ok(data) => data,
        Err(_) => panic!("could not convert cargo tree output from UTF8 to str.")
    };

    // just basic filtering for now, without checking for features or potentially checking accuracy of dependencies in cargo metadata

    let mapped_tree_data_lines: Vec<String> = tree_data
        .lines()
        .map(|string| string.split(" (").next().unwrap().to_string())
        .collect();
    
    HashSet::from_iter(mapped_tree_data_lines)

}

#[test]
fn baseline_matches_cargo_tree() {

    check_environment();

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(FIXED_FEATURES)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_liboscore_provide_abort_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[0];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_liboscore_provide_assert_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[1];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_hwrng_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[2];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_random_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[3];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_dhcpv4_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[4];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_ipv4_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[5];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_semihosting_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[6];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_single_core_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[7];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_executor_interrupt_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[8];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_defmt_rtt_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[9];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_panic_printing_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[10];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_defmt_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[11];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_debug_console_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[12];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_usb_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[13];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_usb_ethernet_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[14];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_coap_transport_udp_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[15];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn without_coap_matches_cargo_tree() {

    check_environment();

    let removal_feature = generate_fixed_feature_list()[16];

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = context.build_command.features.replace(removal_feature, "");
    let tree_features_removed = FIXED_FEATURES.replace(removal_feature, "");

    assert_eq!(context.build_command().features, tree_features_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_removed)
        .output()
        .expect("cargo tree (fixed command) failed")
        .stdout;

    let fixed_tree_set = parse_fixed_tree_data(command_output);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}

#[test]
fn no_features_matches_cargo_tree() {

    check_environment();

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(Some(Path::new(BUILD_COMMAND_FIXTURE_PATH)));
    
    context.build_command.features = "--features=".to_string();
    let tree_features_all_removed = "--features=";

    assert_eq!(context.build_command().features, tree_features_all_removed);

    // generate regular/fixed tree set
    let command_output = Command::new("cargo")
        .envs(FIXED_ENVS.iter().map(|entry| *entry))
        .current_dir(PATHS.ariel_os)
        .arg("tree")
        .arg("--manifest-path")
        .arg(FIXED_MANIFEST_PATH)
        .arg("--prefix")
        .arg("none")
        .arg(tree_features_all_removed)
        .output()
        .expect("cargo tree (fixed command) failed");
        //.stdout;

    println!("{}", String::from_utf8(command_output.stderr).unwrap());

    let fixed_tree_set = parse_fixed_tree_data(command_output.stdout);
    let tool_tree_set = generate_cargo_tree_data(&context);

    assert_eq!(fixed_tree_set, tool_tree_set);
}
