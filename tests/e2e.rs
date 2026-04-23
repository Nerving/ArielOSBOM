mod common;

use std::{
    collections::HashSet, 
    io::Error,
    path::{Path, PathBuf}, 
    process::{Output},
};

use jsonschema;

use common::{
    *,
    CONSTPATHS as PATHS,
};
use arielosbom::{
    ArielOsBuildContext,
    tree,
};


const TEMP_FULL_FILE_NAME_MAIN_REPO: &str = "e2e-main-repo_nrf52840dk.1-6.cdx.json";
const TEMP_FULL_FILE_NAME_OUT_OF_TREE: &str = "e2e-oot_nrf52840dk.1-6.cdx.json";

fn generate_build_context(example: bool) -> ArielOsBuildContext {
    
    let (root_path, manifest_path, import_path);

    if example {
        root_path = PathBuf::from(PATHS.ariel_os);
        manifest_path = Path::new("examples").join("coap-client").join("Cargo.toml");
        import_path = PathBuf::from(".")
    } else {
        root_path = PathBuf::from(PATHS.out_of_tree);
        manifest_path = PathBuf::from("Cargo.toml");
        import_path = PathBuf::from("../ariel-os");
    }
    
    ArielOsBuildContext::from_paths(
        &root_path, 
        &manifest_path, 
        &PathBuf::from("Cargo.lock"), 
        &import_path, 
        &"nrf52840dk".to_string())

}

fn generate_sbom(context: &ArielOsBuildContext, output_name: &str) -> Result<Output, Error> {
    
    test_binary(
        Some(create_e2e_envs()),
        context.root_path(), 
        &vec!["cdx_1.6"], 
        Some(vec!["nrf52840dk"]), 
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

    let mut context = generate_build_context(true);
    context.get_build_command();

    // generate SBOM
    let output = generate_sbom(&context, "e2e-main-repo");

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_MAIN_REPO).exists(), "failed to find generated SBOM file");
    
    // check if CycloneDx conform
    let cyclonedx_16_schema = parse_sbom(
        &Path::new(PATHS.schemata).join("cyclonedx_1.6.json"), 
        "CycloneDx 1.6 schema");
    
    let to_validate = parse_sbom(
        &Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_MAIN_REPO), 
        "error_message"
    );

    assert!(jsonschema::is_valid(&cyclonedx_16_schema, &to_validate));

    // check if components match

    let mut component_set: HashSet<String> = HashSet::new();
    let components = &to_validate["components"].as_array().unwrap();
    for component in components.iter() {
        component_set.insert(format!("{} v{}", component["name"], component["version"]).replace("\"", ""));
    }

    let cargo_tree_set = tree::generate_cargo_tree_data(&context);

    assert!(cargo_tree_set.symmetric_difference(&component_set).collect::<HashSet<&String>>().is_empty(), "SBOM components and cargo tree output do not match");
    
}

#[test]
fn e2e_out_of_tree() {

    common::check_environment();

    // TODO: implement options for other/more/all examples, builders?

    let mut context = generate_build_context(false);
    context.get_build_command();

    // generate SBOM
    let output = generate_sbom(&context, "e2e-oot");

    assert_sbom_generation_status(output);

    assert!(Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_OUT_OF_TREE).exists(), "failed to find generated SBOM file");
    
    // check if CycloneDx conform
    let cyclonedx_16_schema = parse_sbom(
        &Path::new(PATHS.schemata).join("cyclonedx_1.6.json"), 
        "CycloneDx 1.6 schema");
    
    let to_validate = parse_sbom(
        &Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_OUT_OF_TREE), 
        "error_message"
    );
    
    assert!(jsonschema::is_valid(&cyclonedx_16_schema, &to_validate));

    // check if components match

    let mut component_set: HashSet<String> = HashSet::new();
    let components = &to_validate["components"].as_array().unwrap();
    for component in components.iter() {
        component_set.insert(format!("{} v{}", component["name"], component["version"]).replace("\"", ""));
    }
    
    let cargo_tree_set = tree::generate_cargo_tree_data(&context);

    assert!(cargo_tree_set.symmetric_difference(&component_set).collect::<HashSet<&String>>().is_empty(), "SBOM components and cargo tree output do not match");
    
}