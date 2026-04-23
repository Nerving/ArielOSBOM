//      https://cyclonedx.org/docs/1.7/json/#
#![allow(non_snake_case,non_camel_case_types)]

use std::{
    env,
    fmt::Debug,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Local};
use semver::Version;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::component::{Component as RawComponent, Dependency as RawDependency};
use crate::sbom::{CycloneDxSpecVersion, FileFormat, RawSbom, generate_sbom_timestamp};


#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CycloneDxSbomV1_6 {
    bomFormat: String,
    specVersion: CycloneDxSpecVersion,

    #[serde(serialize_with = "uuid::serde::urn::serialize")]
    serialNumber: Uuid,

    metadata: CycloneDxMetadataV1_6,
    components: Vec<CycloneDxComponentV1_6>,
    dependencies: Vec<CycloneDxDependencyV1_6>,
}

impl CycloneDxSbomV1_6 {
    
    pub fn default() -> CycloneDxSbomV1_6 {
        CycloneDxSbomV1_6 {
            bomFormat: "CycloneDX".into(), 
            specVersion: CycloneDxSpecVersion::V1_6, 
            serialNumber: match env::var("TESTING_DETERMINISTIC") {
                Ok(value) if value == "1" => Uuid::default(),
                _ => Uuid::new_v4()
            },
            metadata: CycloneDxMetadataV1_6 { 
                timestamp: None, // timestamp will be set before writing to file
                tools: CycloneDxToolsV1_6 {
                    components: vec![CycloneDxComponentV1_6::generate_tool_component()], 
                },
                manufacturer: CycloneDxManufacturerV1_6::generate_tool_component_manufacturer(),
            }, 
            components: vec![], 
            dependencies: vec![],
        }
    }

    pub fn from_raw(raw_sbom: &RawSbom) -> CycloneDxSbomV1_6 {
        let mut cdx_bom = CycloneDxSbomV1_6::default();

        for component in &raw_sbom.components {
            cdx_bom.components.push(CycloneDxComponentV1_6::from_raw(component));
            cdx_bom.dependencies.push(CycloneDxDependencyV1_6::from_raw(component.id.clone(), &component.dependencies));
        }

        cdx_bom
    }

    pub fn write_to_file(&mut self, file_name: &str, output_dir: &Path, builder: &str) {
        let file_format = FileFormat::Json;
        let full_file_name = format!("{}_{}.1-6.cdx.{}", file_name, builder, file_format);
        let mut file = match File::create([output_dir, Path::new(&full_file_name)].iter().collect::<PathBuf>()) {
            Ok(file) => file,
            Err(e) => panic!("Could not create file: {}: {}", full_file_name, e),
        };

        self.metadata.timestamp = generate_sbom_timestamp();

        file.write_all(serde_json::
                            to_string_pretty(&self)
                            .unwrap()
                            .as_bytes()
                        ).expect("Could not write SBOM data to file.");
    }

    pub fn convert_from_raw_and_write_to_file(raw_sbom: &RawSbom, file_name: &str, output_dir: &Path, builder: &str) {
        let mut cdx_bom = CycloneDxSbomV1_6::from_raw(raw_sbom);
        cdx_bom.write_to_file(file_name, output_dir, builder);
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxMetadataV1_6 {
    timestamp: Option<DateTime<Local>>,
    tools: CycloneDxToolsV1_6,
    manufacturer: CycloneDxManufacturerV1_6,
    //component: CycloneDxComponentV1_6,
    //properties: Vec<CycloneDxPropertyV1_6,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxToolsV1_6 {
    components: Vec<CycloneDxComponentV1_6>
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxComponentV1_6 {
    name: String,

    #[serde(rename = "type")]
    component_type: CycloneDxComponentTypeV1_6,

    version: Version,

    #[serde(rename = "bom-ref")]
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<CycloneDxBomRefV1_6>,

    manufacturer: Option<CycloneDxManufacturerV1_6>,  // needs manufacturer according to BSI spec for URL if no email to provide

    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<Vec<CycloneDxLicenseExpressionV1_6>>, // just License expression for now

    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>, // proper purl later

    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Vec<CycloneDxHashV1_6>>, // BSI requires SHA-512 hash

    externalReferences: Vec<CycloneDxExternalReferenceV1_6>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Vec<CycloneDxPropertyV1_6>>,

    // to address (for BSI): 
        // filename, SHA-512 hash (of what specifically?)
        // exec/arch/struc property (default for library: arch/struc; main application: exec)
        // hash source code
        // uri deployable/security text
}

impl CycloneDxComponentV1_6 {
    fn generate_tool_component() -> CycloneDxComponentV1_6 {
        CycloneDxComponentV1_6 { 
            name: "ArielOSBOM (provisional name)".into(), 
            component_type: CycloneDxComponentTypeV1_6::application, 
            version: Version::new(0, 0, 0), 
            id: None, 
            manufacturer: Some(CycloneDxManufacturerV1_6::generate_tool_component_manufacturer()),
            licenses: Some(vec!["MIT License".to_string().into()]), 
            purl: None, 
            hashes: None, 
            externalReferences: vec![
                CycloneDxExternalReferenceV1_6::generate_tool_component_reference(),
            ],
            properties: None 
        }
    }

    fn from_raw(raw_component: &RawComponent) -> CycloneDxComponentV1_6 {
        CycloneDxComponentV1_6 { 
            name: raw_component.name.clone(), 
            component_type: CycloneDxComponentTypeV1_6::library, //just defaulting for now 
            version: raw_component.version.clone(), 
            id: Some(raw_component.id.clone().into()), 
            manufacturer: Some(CycloneDxManufacturerV1_6::from_raw_component(raw_component)), 
            licenses: Some(vec![
                match raw_component.licenses.clone() {
                    Some(license_statement) => license_statement.into(),
                    _ => String::new().into()
                }]),
            purl: None, 
            hashes: Some(raw_component.identifiers
                .iter()
                .map(
                    |hash| CycloneDxHashV1_6::from_lock_checksum(hash.clone())
                )
                .collect()
            ), 
            externalReferences: CycloneDxExternalReferenceV1_6::from_raw_component(raw_component), 
            properties: Some(vec![]) }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxDependencyV1_6 {
    #[serde(rename = "ref")]
    bom_ref: CycloneDxBomRefV1_6,
    dependsOn: Vec<CycloneDxBomRefV1_6>,
    // provides:
}

impl CycloneDxDependencyV1_6 {
    fn from_raw(component_id: String, raw_dependencies: &Vec<RawDependency>) -> CycloneDxDependencyV1_6 {
        CycloneDxDependencyV1_6 { 
            bom_ref: component_id.into(), 
            dependsOn: raw_dependencies
                .iter()
                .map(
                    |dep| dep.id.clone().into()
                )
                .collect()
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxPropertyV1_6 {
    name: String,
    value: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxManufacturerV1_6 {
    //bom-ref,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>, // type temporary?

    url: Vec<String>, // type temporary?
    
    //contact,
}

impl CycloneDxManufacturerV1_6 {
    fn generate_tool_component_manufacturer() -> CycloneDxManufacturerV1_6 {
        CycloneDxManufacturerV1_6 { name: None, address: None, url: vec!["https://github.com/Nerving/ArielOSBOM".into()] }
    }

    fn from_raw_component(raw_component: &RawComponent) -> CycloneDxManufacturerV1_6 {
        CycloneDxManufacturerV1_6 { 
            name: Some(raw_component.creators.clone().join(", ")),
            address: None,
            url: match raw_component.uri_source_code.clone() {
                Some(url) => vec![url],
                None => vec![],
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxLicenseExpressionV1_6 {
    expression: String,
}

impl From<String> for CycloneDxLicenseExpressionV1_6 {
    fn from(value: String) -> Self {
        CycloneDxLicenseExpressionV1_6 { expression: value }
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxBomRefV1_6(String);

impl From<String> for CycloneDxBomRefV1_6 {
    fn from(value: String) -> Self {
        CycloneDxBomRefV1_6(value)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxHashV1_6 {
    alg: CycloneDxHashAlgV1_6,
    content: String, // temporary type
}

impl CycloneDxHashV1_6 {
    fn from_lock_checksum(checksum: String) -> CycloneDxHashV1_6 {
        CycloneDxHashV1_6 { 
            alg: CycloneDxHashAlgV1_6::SHA_256, 
            content: checksum }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxExternalReferenceV1_6 {
    url: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,

    #[serde(rename = "type")]
    reference_type: CycloneDxExternalReferenceTypeV1_6,

    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Vec<CycloneDxHashV1_6>>,
}

impl CycloneDxExternalReferenceV1_6 {
    fn generate_tool_component_reference() -> CycloneDxExternalReferenceV1_6 {
        CycloneDxExternalReferenceV1_6 { 
            url: "https://github.com/Nerving/ArielOSBOM".into(), 
        comment: None, 
        reference_type: CycloneDxExternalReferenceTypeV1_6::source_distribution, 
        hashes: None, 
        }
    }

    fn from_uri_source_code(uri: String) -> CycloneDxExternalReferenceV1_6 {
        CycloneDxExternalReferenceV1_6 { 
            url: uri.clone(), 
            comment: None, 
            reference_type: CycloneDxExternalReferenceTypeV1_6::source_distribution, 
            hashes: None, 
        }
    }

    fn from_raw_component(raw_component: &RawComponent) -> Vec<CycloneDxExternalReferenceV1_6> {
        let mut references_vector = vec![];

        if let Some(uri_source_code) = raw_component.uri_source_code.clone() {
            references_vector.push(CycloneDxExternalReferenceV1_6::from_uri_source_code(uri_source_code));
        }

        references_vector
    }
}

// ENUMS

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CycloneDxComponentTypeV1_6 {
    application,
    framework,
    library,
    container,
    platform,
    operating_system,
    device,
    device_driver,
    firmware,
    file,
    machine_learning_model,
    data,
    cryptographic_asset
}

#[derive(Clone, Deserialize, Debug, PartialEq, Eq)]
enum CycloneDxHashAlgV1_6 {
    MD5,
    SHA_1,
    SHA_256,
    SHA_384,
    SHA_512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    BLAKE2b_256,
    BLAKE2b_384,
    BLAKE2b_512,
    BLAKE3,
}

impl Serialize for CycloneDxHashAlgV1_6 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer 
    {
        let replaced = format!("{:?}", self).replace("_", "-");
        serializer.serialize_str(&replaced)    
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CycloneDxExternalReferenceTypeV1_6 {
    vcs,
    website,
    bom,
    documentation,
    source_distribution,
    distribution,
    license,
    // list not complete
}   


