use crate::component::{Component, Dependency};
use crate::CycloneDxSbomV1_7;

use cargo_lock::{Checksum, Lockfile};
use cargo_metadata::{DependencyKind, Metadata};
use chrono::{DateTime, Local};
use serde::{Serialize, Deserialize};

use std::{
    collections::{HashMap},
    fmt::{Formatter},
    fs::{File},
    io::{Write},
};

pub mod cyclonedx;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct RawSbom {
    pub bom_metadata: BomMetadata,
    pub components: Vec<Component>,
    #[serde(skip_serializing)]
    component_map: HashMap<String, usize>   // not even used anymore
}

impl RawSbom {

    pub fn new() -> RawSbom {
        RawSbom {
            bom_metadata: BomMetadata { 
                creator: "ArielOSBOM (provisional name)".into(),
                timestamp: None,
             },
            components: vec![],
            component_map: HashMap::new()
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
            self.component_map.insert(package.id.repr.clone(), index);
            index += 1;
        }
    }

    pub fn write_to_file(&mut self, file_name: &str) {
        let file_format = FileFormat::Json;
        let mut file = match File::create(format!("./output/{}.raw.{}", file_name, file_format)) {
            Ok(file) => file,
            Err(e) => panic!("Could not create file: {}.{}: {}", file_name, file_format, e),
        };

        self.bom_metadata.timestamp = Some(Local::now());

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

// potentially changing serialization later for diff. formats; or as mentioned just make this based off. diff structs altogether
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum BomFormat {
    Raw,
    SPDX,
    CDX,
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
                BomFormat::CDX => "Cyclone-DX"
            }
        )
    }
}

pub fn write_sbom_to_file(sbom: &mut RawSbom, bom_format: &BomFormat, output_name: &str) {
    match bom_format {
        BomFormat::Raw => sbom.write_to_file(&output_name),
        BomFormat::SPDX => println!("No SPDX conversion currently"),
        BomFormat::CDX => CycloneDxSbomV1_7::convert_from_raw_and_write_to_file(&sbom, output_name),
    }
}