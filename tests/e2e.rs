mod common;

use std::{ 
    io::Error,
    path::Path, 
    process::Output,
};

use arielosbom::{
    ArielOsBuildContext,
};
use jsonschema;
use serde_json::Value;

use common::{
    assert_sbom_generation_status,
    CONSTPATHS as PATHS,
    create_e2e_envs,
    generate_example_build_context,
    generate_out_of_tree_build_context,
    parse_sbom,
    STANDARD_BUILDER,
    STANDARD_EXAMPLE,
    test_binary,
};

const FIXTURE_DIRECTORY_PATH: &str = "tests/fixtures/e2e";
const FIXTURE_MAIN_REPO_NAME: &str = "e2e-example-fixture_nrf52840dk.1-6.cdx.json";
const FIXTURE_OOT_NAME: &str = "e2e-oot-fixture_nrf52840dk.1-6.cdx.json";

const TEMP_FULL_FILE_NAME_MAIN_REPO: &str = "e2e-main-repo_nrf52840dk.1-6.cdx.json";
const TEMP_FULL_FILE_NAME_OUT_OF_TREE: &str = "e2e-oot_nrf52840dk.1-6.cdx.json";

fn generate_sbom(context: &ArielOsBuildContext, output_name: &str) -> Result<Output, Error> {
    
    test_binary(
        Some(create_e2e_envs()),
        context.root_path(), 
        &vec!["cdx_1.6"], 
        Some(vec![STANDARD_BUILDER]), 
        output_name, 
        Some(context.manifest_path()), 
        None, 
        Some(context.import_path()),
    )

}

#[test]
fn e2e_main_repo() {

    common::check_environment();

    // TODO: implement options for other/more/all examples, builders?

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(None);

    // generate SBOM
    let output = generate_sbom(&context, "e2e-main-repo");

    assert_sbom_generation_status(output, true);

    assert!(Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_MAIN_REPO).exists(), "failed to find generated SBOM file");
    
    // check if CycloneDx conform
    let cyclonedx_16_schema = parse_sbom(
        &Path::new(PATHS.schemata).join("cyclonedx_1.6.json"), 
        "CycloneDx 1.6 schema");
    
    let mut to_validate = parse_sbom(
        &Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_MAIN_REPO), 
        "error_message"
    );

    assert!(jsonschema::is_valid(&cyclonedx_16_schema, &to_validate));

    // remove timestamp and uuid
    to_validate["metadata"]["timestamp"] = Value::String("".to_string());
    to_validate["serialNumber"] = Value::String("".to_string());

    let fixture = parse_sbom(&Path::new(FIXTURE_DIRECTORY_PATH).join(FIXTURE_MAIN_REPO_NAME), "SBOM fixture");

    assert_eq!(to_validate, fixture , "generated SBOM does not match fixture");
    
}

#[test]
fn e2e_out_of_tree() {

    common::check_environment();

    // TODO: implement options for other/more/all examples, builders?

    let mut context = generate_out_of_tree_build_context(STANDARD_BUILDER);
    context.get_build_command(None);

    // generate SBOM
    let output = generate_sbom(&context, "e2e-oot");

    assert_sbom_generation_status(output, true);

    assert!(Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_OUT_OF_TREE).exists(), "failed to find generated SBOM file");
    
    // check if CycloneDx conform
    let cyclonedx_16_schema = parse_sbom(
        &Path::new(PATHS.schemata).join("cyclonedx_1.6.json"), 
        "CycloneDx 1.6 schema");
    
    let mut to_validate = parse_sbom(
        &Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_OUT_OF_TREE), 
        "error_message"
    );
    
    assert!(jsonschema::is_valid(&cyclonedx_16_schema, &to_validate));

    // remove timestamp and uuid
    to_validate["metadata"]["timestamp"] = Value::String("".to_string());
    to_validate["serialNumber"] = Value::String("".to_string());

    let fixture = parse_sbom(&Path::new(FIXTURE_DIRECTORY_PATH).join(FIXTURE_OOT_NAME), "SBOM fixture");

    assert_eq!(to_validate, fixture , "generated SBOM does not match fixture");
    
}