use crate::component::{Component, Dependency};

use cargo_lock::{Checksum, Lockfile};
use cargo_metadata::{DependencyKind, Metadata};
use chrono::{NaiveDateTime, Utc};
use serde::{Serialize, Deserialize};

use std::{
    collections::{HashMap},
    fmt::{Formatter},
    fs::{File},
    io::{Write},
};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct SBOM {

    #[serde(skip_serializing)]
    pub bom_format: BomFormat,

    //pub file_format: FileFormat, outside of actual bom because base content should be independent of format?

    pub bom_metadata: BomMetadata,

    pub components: Vec<Component>,

    // maybe add dependencies as its own Vec<> later afterall for simpler serializing according to other formats as well
        // otherwise maybe diff struct for the other formats if that makes sense/is the better idea, will see

    #[serde(skip_serializing)]
    component_map: HashMap<String, usize>
}

impl SBOM {

    pub fn new(format: BomFormat) -> SBOM {
        SBOM {
            bom_format: format,
            bom_metadata: BomMetadata { 
                creator: "ArielOSBOM".into(),
                timestamp: Utc::now().naive_utc(),
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

    // file format as input later maybe to loop through calls of this function?
    pub fn write_to_file(&self, file_name: &str) {
        let file_format = FileFormat::Json;
        let mut file = match File::create(format!("./{}.{}", file_name, file_format)) {
            Ok(file) => file,
            Err(e) => panic!("Could not create file: {}.{}: {}", file_name, file_format, e),
        };

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
    timestamp: NaiveDateTime,
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