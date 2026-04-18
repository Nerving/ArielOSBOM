use crate::component::{Component, Dependency};
use crate::sbom::cyclonedx_v16::CycloneDxSbomV1_6;
use crate::sbom::cyclonedx_v17::CycloneDxSbomV1_7;

use cargo_lock::{Checksum, Lockfile};
use cargo_metadata::{DependencyKind, Metadata};
use chrono::{DateTime, Local};
use serde::{Serialize, Deserialize};

use std::{
    collections::{HashMap},
    env,
    fmt::{Formatter},
    fs::{File},
    io::{Write},
    path::{Path, PathBuf},
};

pub mod cyclonedx_v16;
pub mod cyclonedx_v17;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct RawSbom {
    pub bom_metadata: BomMetadata,
    pub components: Vec<Component>,
}

impl RawSbom {

    pub fn new() -> RawSbom {
        RawSbom {
            bom_metadata: BomMetadata { 
                creator: "ArielOSBOM (provisional name)".into(),
                timestamp: None,
             },
            components: vec![],
        }
    }

    pub fn convert_cargo_metadata_packages_to_components(&mut self, metadata: &Metadata, lockdata: &Lockfile) {
        
        // map Cargo.lock checksums to packages
        let mut lock_hash: HashMap<(String, String), Checksum> = HashMap::new();
        for lock_package in lockdata.packages.iter() {
            if let Some(checksum) = &lock_package.checksum {     
                lock_hash.insert((lock_package.name.to_string(), lock_package.version.to_string().clone()), checksum.clone());
            }
        }

        assert!(metadata.packages.len() == metadata.resolve.as_ref().unwrap().nodes.len());
        let mut index = 0;
        for package in metadata.packages.iter() {
            self.components
                .push(Component::create_component_from_metadata(
                    package, 
                    lock_hash.get(&(package.name.to_string(), package.version.to_string())),
                    metadata.resolve
                        .as_ref()
                        .unwrap()
                        .nodes[index].deps
                        .iter()
                        .map(|dep| Dependency {
                            id: dep.pkg.repr.clone(), 
                            build: dep.dep_kinds
                                .iter()
                                .any(|info| info.kind == DependencyKind::Build)
                            }
                        )
                        .collect()
                ));
            index += 1;
        }
    }

    pub fn write_to_file(&mut self, file_name: &str, output_dir: &Path, builder: &str) {
        let file_format = FileFormat::Json;
        let full_file_name = format!("{}_{}.raw.{}", file_name, builder, file_format);
        let mut file = match File::create([output_dir, Path::new(&full_file_name)].iter().collect::<PathBuf>()) {
            Ok(file) => file,
            Err(e) => panic!("Could not create file: {}: {}", full_file_name, e),
        };

        self.bom_metadata.timestamp = generate_sbom_timestamp();

        file.write_all(serde_json::
                            to_string(&self)
                            .unwrap()
                            .as_bytes()
                        ).expect("Could not write SBOM data to file.");
    }

}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct BomMetadata {
    creator: String,
    timestamp: Option<DateTime<Local>>,
    // target
    // other BomFormat related metadata
    // other general project related data? (features, protocols, program size, ...)
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum BomFormat {
    Raw,
    SPDX,
    CDX(CycloneDxSpecVersion),
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum FileFormat {
    Json,
}

// remove later if/when not needed; unless for logging
impl std::fmt::Display for BomFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", match self {
                BomFormat::Raw => "Raw",
                BomFormat::SPDX => "SPDX",
                BomFormat::CDX(CycloneDxSpecVersion::V1_6) => "CycloneDX 1.6",
                BomFormat::CDX(CycloneDxSpecVersion::V1_7) => "CycloneDX 1.7"
            }
        )
    }
}

pub fn write_sbom_to_file(sbom: &mut RawSbom, bom_format: &BomFormat, output_name: &str, output_dir: &Path, builder: &str) {
    match bom_format {
        BomFormat::Raw => sbom.write_to_file(&output_name, &output_dir, builder),
        BomFormat::SPDX => println!("No SPDX conversion currently"),
        BomFormat::CDX(CycloneDxSpecVersion::V1_6) => CycloneDxSbomV1_6::convert_from_raw_and_write_to_file(&sbom, output_name, output_dir, builder),
        BomFormat::CDX(CycloneDxSpecVersion::V1_7) => CycloneDxSbomV1_7::convert_from_raw_and_write_to_file(&sbom, output_name, output_dir, builder),
    }
}

pub fn generate_sbom_timestamp() -> Option<DateTime<Local>> {
    
    match env::var("TESTING_DETERMINISTIC") {
        Ok(value) if value == "1" => None,
        _ => Some(Local::now())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum CycloneDxSpecVersion {
    #[serde(rename = "1.6")]
    V1_6,

    #[serde(rename = "1.7")]
    V1_7,
}