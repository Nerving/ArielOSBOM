//      https://cyclonedx.org/docs/1.7/json/#
#![allow(non_snake_case, non_camel_case_types)]

use std::{
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
pub struct CycloneDxSbomV1_7 {
    bomFormat: String,
    specVersion: CycloneDxSpecVersion,

    #[serde(serialize_with = "uuid::serde::urn::serialize")]
    serialNumber: Uuid,

    metadata: CycloneDxMetadataV1_7,
    components: Vec<CycloneDxComponentV1_7>,
    dependencies: Vec<CycloneDxDependencyV1_7>,
}

impl Default for CycloneDxSbomV1_7 {
    fn default() -> Self {
        CycloneDxSbomV1_7 {
            bomFormat: "CycloneDX".into(),
            specVersion: CycloneDxSpecVersion::V1_7,
            serialNumber: Uuid::new_v4(),
            metadata: CycloneDxMetadataV1_7 {
                timestamp: None, // timestamp will be set before writing to file
                tools: CycloneDxToolsV1_7 {
                    components: vec![CycloneDxComponentV1_7::generate_tool_component()],
                },
                manufacturer: CycloneDxManufacturerV1_7::generate_tool_component_manufacturer(),
                component: None,
            },
            components: vec![],
            dependencies: vec![],
        }
    }
}

impl CycloneDxSbomV1_7 {
    pub fn from_raw(raw_sbom: &RawSbom) -> CycloneDxSbomV1_7 {
        let mut cdx_bom = CycloneDxSbomV1_7::default();

        for (index, component) in raw_sbom.components.iter().enumerate() {
            let mut cdx_component = CycloneDxComponentV1_7::from_raw(component);
            cdx_bom.dependencies.push(CycloneDxDependencyV1_7::from_raw(
                component.id.clone(),
                &component.dependencies,
            ));

            if index == raw_sbom.bom_metadata.root_component_index {
                // statically for now as the root component is the described application
                cdx_component.component_type = CycloneDxComponentTypeV1_7::application;
                cdx_bom.metadata.component = Some(cdx_component);
            } else {
                cdx_bom.components.push(cdx_component);
            }
        }

        cdx_bom
    }

    pub fn write_to_file(&mut self, file_name: &str, output_dir: &Path, builder: &str) {
        let file_format = FileFormat::Json;
        let full_file_name = format!("{}_{}.1-7.cdx.{}", file_name, builder, file_format);
        let mut file = match File::create(
            [output_dir, Path::new(&full_file_name)]
                .iter()
                .collect::<PathBuf>(),
        ) {
            Ok(file) => file,
            Err(e) => panic!("Could not create file: {}: {}", full_file_name, e),
        };

        self.metadata.timestamp = generate_sbom_timestamp();

        file.write_all(serde_json::to_string_pretty(&self).unwrap().as_bytes())
            .expect("Could not write SBOM data to file.");
    }

    pub fn convert_from_raw_and_write_to_file(
        raw_sbom: &RawSbom,
        file_name: &str,
        output_dir: &Path,
        builder: &str,
    ) {
        let mut cdx_bom = CycloneDxSbomV1_7::from_raw(raw_sbom);
        cdx_bom.write_to_file(file_name, output_dir, builder);
    }

    pub fn default_uuid(&mut self) {
        self.serialNumber = Uuid::default();
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxMetadataV1_7 {
    timestamp: Option<DateTime<Local>>,
    tools: CycloneDxToolsV1_7,
    manufacturer: CycloneDxManufacturerV1_7,
    component: Option<CycloneDxComponentV1_7>,
    //properties: Vec<CycloneDxPropertyV1_7,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxToolsV1_7 {
    components: Vec<CycloneDxComponentV1_7>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxComponentV1_7 {
    name: String,

    #[serde(rename = "type")]
    component_type: CycloneDxComponentTypeV1_7,

    version: Version,

    #[serde(rename = "bom-ref")]
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<CycloneDxBomRefV1_7>,

    manufacturer: Option<CycloneDxManufacturerV1_7>, // needs manufacturer according to BSI spec for URL if no email to provide

    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<Vec<CycloneDxLicenseExpressionV1_7>>, // just License expression for now

    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>, // proper purl later

    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Vec<CycloneDxHashV1_7>>, // BSI requires SHA-512 hash

    externalReferences: Vec<CycloneDxExternalReferenceV1_7>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Vec<CycloneDxPropertyV1_7>>,
    // to address (for BSI):
    // filename, SHA-512 hash (of what specifically?)
    // exec/arch/struc property (default for library: arch/struc; main application: exec)
    // hash source code
    // uri deployable/security text
}

impl CycloneDxComponentV1_7 {
    fn generate_tool_component() -> CycloneDxComponentV1_7 {
        CycloneDxComponentV1_7 {
            name: "ArielOSBOM (provisional name)".into(),
            component_type: CycloneDxComponentTypeV1_7::application,
            version: Version::new(0, 0, 0),
            id: None,
            manufacturer: Some(CycloneDxManufacturerV1_7::generate_tool_component_manufacturer()),
            licenses: Some(vec!["MIT License".to_string().into()]),
            purl: None,
            hashes: None,
            externalReferences: vec![
                CycloneDxExternalReferenceV1_7::generate_tool_component_reference(),
            ],
            properties: None,
        }
    }

    fn from_raw(raw_component: &RawComponent) -> CycloneDxComponentV1_7 {
        CycloneDxComponentV1_7 {
            name: raw_component.name.clone(),
            component_type: CycloneDxComponentTypeV1_7::library, //just defaulting for now
            version: raw_component.version.clone(),
            id: Some(raw_component.id.clone().into()),
            manufacturer: Some(CycloneDxManufacturerV1_7::from_raw_component(raw_component)),
            licenses: Some(vec![match raw_component.licenses.clone() {
                Some(license_statement) => license_statement.into(),
                _ => String::new().into(),
            }]),
            purl: None,
            hashes: Some(
                raw_component
                    .identifiers
                    .iter()
                    .map(|hash| CycloneDxHashV1_7::from_lock_checksum(hash.clone()))
                    .collect(),
            ),
            externalReferences: CycloneDxExternalReferenceV1_7::from_raw_component(raw_component),
            properties: Some(vec![]),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxDependencyV1_7 {
    #[serde(rename = "ref")]
    bom_ref: CycloneDxBomRefV1_7,
    dependsOn: Vec<CycloneDxBomRefV1_7>,
    // provides:
}

impl CycloneDxDependencyV1_7 {
    fn from_raw(
        component_id: String,
        raw_dependencies: &[RawDependency],
    ) -> CycloneDxDependencyV1_7 {
        CycloneDxDependencyV1_7 {
            bom_ref: component_id.into(),
            dependsOn: raw_dependencies
                .iter()
                .map(|dep| dep.id.clone().into())
                .collect(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxPropertyV1_7 {
    name: String,
    value: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxManufacturerV1_7 {
    //bom-ref,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>, // type temporary?

    #[serde(skip_serializing_if = "Vec::is_empty")]
    url: Vec<String>, // type temporary?

                      //contact,
}

impl CycloneDxManufacturerV1_7 {
    fn generate_tool_component_manufacturer() -> CycloneDxManufacturerV1_7 {
        CycloneDxManufacturerV1_7 {
            name: None,
            address: None,
            url: vec!["https://github.com/Nerving/ArielOSBOM".into()],
        }
    }

    fn from_raw_component(raw_component: &RawComponent) -> CycloneDxManufacturerV1_7 {
        let name_if_registy = if raw_component.creators.is_empty() {
            None
        } else {
            Some(raw_component.creators.clone().join(", "))
        };

        let (url, name) = if !raw_component.id.starts_with("registry+") {
            // if external: do not provide upstream
            if let Some(vcs) = raw_component.vcs.clone() {
                (vcs.rsplit_once("/tree/").unwrap().0.to_string(), None)
            } else {
                ("".into(), None)
            }
        } else if let Some(url) = raw_component.metadata_website.clone() {
            (url, name_if_registy)
        } else if let Some(url) = raw_component.metadata_repository.clone() {
            (url, name_if_registy)
        } else {
            ("".into(), name_if_registy)
        };

        CycloneDxManufacturerV1_7 {
            name,
            address: None,
            url: match url.len() {
                0 => vec![],
                _ => vec![url],
            },
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxLicenseExpressionV1_7 {
    expression: String,
    acknowledgement: String,
}

impl From<String> for CycloneDxLicenseExpressionV1_7 {
    fn from(value: String) -> Self {
        CycloneDxLicenseExpressionV1_7 {
            expression: value,
            acknowledgement: "declared".into(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxBomRefV1_7(String);

impl From<String> for CycloneDxBomRefV1_7 {
    fn from(value: String) -> Self {
        CycloneDxBomRefV1_7(value)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxHashV1_7 {
    alg: CycloneDxHashAlgV1_7,
    content: String, // temporary type
}

impl CycloneDxHashV1_7 {
    fn from_lock_checksum(checksum: String) -> CycloneDxHashV1_7 {
        CycloneDxHashV1_7 {
            alg: CycloneDxHashAlgV1_7::SHA_256,
            content: checksum,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
struct CycloneDxExternalReferenceV1_7 {
    url: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,

    #[serde(rename = "type")]
    reference_type: CycloneDxExternalReferenceTypeV1_7,

    #[serde(skip_serializing_if = "Option::is_none")]
    hashes: Option<Vec<CycloneDxHashV1_7>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<Vec<CycloneDxPropertyV1_7>>,
}

impl CycloneDxExternalReferenceV1_7 {
    fn generate_tool_component_reference() -> CycloneDxExternalReferenceV1_7 {
        CycloneDxExternalReferenceV1_7 {
            url: "https://github.com/Nerving/ArielOSBOM".into(),
            comment: None,
            reference_type: CycloneDxExternalReferenceTypeV1_7::vcs,
            hashes: None,
            properties: None,
        }
    }

    fn from_uri_source_code(uri: String) -> CycloneDxExternalReferenceV1_7 {
        CycloneDxExternalReferenceV1_7 {
            url: uri.clone(),
            comment: None,
            reference_type: CycloneDxExternalReferenceTypeV1_7::vcs,
            hashes: None,
            properties: None,
        }
    }

    fn from_raw_component(raw_component: &RawComponent) -> Vec<CycloneDxExternalReferenceV1_7> {
        let mut references_vector = vec![];

        if let Some(vcs) = raw_component.vcs.clone() {
            references_vector.push(CycloneDxExternalReferenceV1_7::from_uri_source_code(vcs));
        }

        references_vector
    }
}

// ENUMS

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CycloneDxComponentTypeV1_7 {
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
    cryptographic_asset,
}

#[derive(Clone, Deserialize, Debug, PartialEq, Eq)]
enum CycloneDxHashAlgV1_7 {
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
    Streebog_256,
    Streebog_512,
}

impl Serialize for CycloneDxHashAlgV1_7 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let replaced = format!("{:?}", self).replace("_", "-");
        serializer.serialize_str(&replaced)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum CycloneDxExternalReferenceTypeV1_7 {
    vcs,
    website,
    bom,
    documentation,
    source_distribution,
    distribution,
    license,
    // list not complete
}
