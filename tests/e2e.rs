mod common;

use std::{
    collections::HashSet,
    env::current_dir,
    fs::{read, remove_file},
    io::Error,
    path::Path,
    process::Output,
};

use arielosbom::{ArielOsBuildContext, CrateId, tree::parse_cargo_tree};
use serde_json::Value;

use common::{
    CONSTPATHS as PATHS, STANDARD_BUILDER, STANDARD_EXAMPLE, assert_sbom_generation_status,
    create_e2e_envs, generate_example_build_context, generate_out_of_tree_build_context,
    parse_sbom, test_binary,
};

const FIXTURE_DIRECTORY_PATH: &str = "tests/fixtures/e2e";
const FIXTURE_MAIN_REPO_NAME: &str = "e2e-example-fixture_nrf52840dk.1-6.cdx.json";

const TEMP_FULL_FILE_NAME_MAIN_REPO: &str = "e2e-main-repo_nrf52840dk.1-6.cdx.json";
const TEMP_FULL_FILE_NAME_OUT_OF_TREE: &str = "e2e-oot_nrf52840dk.1-6.cdx.json";
const OOT_METADATA_FILE_NAME: &str = "e2e-oot_nrf52840dk.metadata.json";
const OOT_TREE_DATA_FILE_NAME: &str = "e2e-oot_nrf52840dk.tree.txt";

fn generate_sbom(
    context: &ArielOsBuildContext,
    output_name: &str,
    emit_cargo_artifacts: bool,
) -> Result<Output, Error> {
    test_binary(
        context,
        Some(create_e2e_envs()),
        //context.root_path(),
        &vec!["cdx_1.6"],
        Some(vec![STANDARD_BUILDER]),
        output_name,
        //Some(context.manifest_path()),
        //None,
        //Some(context.import_path()),
        emit_cargo_artifacts,
    )
}

fn crop_bom_refs(mut sbom: Value, is_fixture: bool) -> Value {
    let root_component = &mut sbom["metadata"]["component"];
    replace_bom_ref_in_entry(root_component, "bom-ref", is_fixture);

    for entry in sbom["components"].as_array_mut().unwrap() {
        replace_bom_ref_in_entry(entry, "bom-ref", is_fixture);
    }

    for entry in sbom["dependencies"].as_array_mut().unwrap() {
        replace_bom_ref_in_entry(entry, "ref", is_fixture);
        replace_bom_ref_in_entry(entry, "dependsOn", is_fixture);
    }

    sbom
}

fn replace_bom_ref_in_entry(entry: &mut Value, field: &str, is_fixture: bool) {
    let project_dir = current_dir().unwrap();

    entry[field] = Value::String(entry[field].to_string().replace(
        if is_fixture {
            "/home/nerving/Thesis/ArielOSBOM"
        } else {
            project_dir.to_str().unwrap()
        },
        "<PATH_TO_PROJECT_ROOT>",
    ));
}

fn remove_old_test_output(file_name: &str) {
    let file_path = Path::new(PATHS.output).join(file_name);
    if file_path.exists() {
        remove_file(file_path).expect("failed to remove old test file");
    }
}

#[test]
fn e2e_main_repo() {
    common::check_environment();
    remove_old_test_output(TEMP_FULL_FILE_NAME_MAIN_REPO);

    // TODO: implement options for other/more/all examples, builders?

    let mut context = generate_example_build_context(STANDARD_EXAMPLE, STANDARD_BUILDER);
    context.get_build_command(None);

    let output = generate_sbom(&context, "e2e-main-repo", false);

    assert_sbom_generation_status(output, true);

    assert!(
        Path::new(PATHS.output)
            .join(TEMP_FULL_FILE_NAME_MAIN_REPO)
            .exists(),
        "failed to find generated SBOM file"
    );

    // check if CycloneDx conform
    let cyclonedx_16_schema: serde_json::Value = parse_sbom(
        &Path::new(PATHS.schemata).join("cyclonedx_1.6.json"),
        "CycloneDx 1.6 schema",
    );

    let mut to_validate = parse_sbom(
        &Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_MAIN_REPO),
        "error_message",
    );

    assert!(jsonschema::is_valid(&cyclonedx_16_schema, &to_validate));

    // compare against fixture
    to_validate["metadata"]["timestamp"] = Value::String("".to_string());
    to_validate["serialNumber"] = Value::String("".to_string());

    let fixture = parse_sbom(
        &Path::new(FIXTURE_DIRECTORY_PATH).join(FIXTURE_MAIN_REPO_NAME),
        "SBOM fixture",
    );

    // crop out path to project route in bom-refs
    let cropped_to_validate_cdx = crop_bom_refs(to_validate, false);
    let cropped_fixture_cdx = crop_bom_refs(fixture, true);

    assert_eq!(
        cropped_fixture_cdx, cropped_to_validate_cdx,
        "generated SBOM does not match fixture"
    );
}

#[test]
fn e2e_out_of_tree() {
    common::check_environment();
    remove_old_test_output(TEMP_FULL_FILE_NAME_OUT_OF_TREE);
    remove_old_test_output(OOT_METADATA_FILE_NAME);
    remove_old_test_output(OOT_TREE_DATA_FILE_NAME);

    // TODO: implement options for other/more/all examples, builders?

    let mut context = generate_out_of_tree_build_context(STANDARD_BUILDER);
    context.get_build_command(None);

    let output = generate_sbom(&context, "e2e-oot", true);

    assert_sbom_generation_status(output, true);

    assert!(
        Path::new(PATHS.output)
            .join(TEMP_FULL_FILE_NAME_OUT_OF_TREE)
            .exists(),
        "failed to find generated SBOM file"
    );
    assert!(
        Path::new(PATHS.output)
            .join(OOT_METADATA_FILE_NAME)
            .exists(),
        "failed to find generated metadata"
    );
    assert!(
        Path::new(PATHS.output)
            .join(OOT_TREE_DATA_FILE_NAME)
            .exists(),
        "failed to find generated tree data"
    );

    // check if CycloneDx conform
    let cyclonedx_16_schema = parse_sbom(
        &Path::new(PATHS.schemata).join("cyclonedx_1.6.json"),
        "CycloneDx 1.6 schema",
    );

    let to_validate = parse_sbom(
        &Path::new(PATHS.output).join(TEMP_FULL_FILE_NAME_OUT_OF_TREE),
        "error_message",
    );

    assert!(jsonschema::is_valid(&cyclonedx_16_schema, &to_validate));

    //  Because of dependency resolution behaviour due do the separate Ariel OS workspace(?),
    //  the import's Cargo.lock file is not considered and thus it cannot be guaranteed that all
    //  dependencies are resolved the same, so a comparison against an old SBOM will eventually fail.
    //  Instead, as done previously, it is compared whether the components match the ones found by cargo tree.

    let mut component_set: HashSet<CrateId> = HashSet::new();
    let root_component = CrateId::from_package_id(
        to_validate["metadata"]["component"]["bom-ref"]
            .as_str()
            .unwrap(),
    );
    component_set.insert(root_component);
    let components = &to_validate["components"].as_array().unwrap();
    for component in components.iter() {
        // println!("{}", component["name"]);
        component_set.insert(CrateId::from_package_id(
            component["bom-ref"].as_str().unwrap(),
        ));
    }

    let cargo_tree = parse_cargo_tree(
        read(Path::new(PATHS.output).join(OOT_TREE_DATA_FILE_NAME))
            .expect("failed to read cargo tree artifact"),
    );
    let cargo_tree_component_list = HashSet::from_iter(cargo_tree.nodes.iter().cloned());

    assert_eq!(
        component_set, cargo_tree_component_list,
        "SBOM components and cargo tree output do not match"
    );
}
