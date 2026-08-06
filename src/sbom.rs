pub mod cyclonedx_v16;
pub mod cyclonedx_v17;

use std::{
    collections::HashMap,
    env,
    fmt::Formatter,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use cargo_lock::Checksum;
use cargo_metadata::{Metadata, PackageId};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::sbom::cyclonedx_v16::CycloneDxSbomV1_6;
use crate::sbom::cyclonedx_v17::CycloneDxSbomV1_7;
use crate::tree::CargoTreeGraph;
use crate::{CrateId, component::Component};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct RawSbom {
    pub bom_metadata: BomMetadata,
    pub components: Vec<Component>,
}

impl RawSbom {
    pub fn empty() -> RawSbom {
        RawSbom {
            bom_metadata: BomMetadata {
                creator: "ArielOSBOM (provisional name)".into(),
                timestamp: None,
            },
            components: vec![],
        }
    }

    pub fn convert_cargo_data_to_components(
        &mut self,
        metadata: &Metadata,
        checksum_map: HashMap<CrateId, Checksum>,
        tree_graph: CargoTreeGraph,
    ) {
        let crate_identifier_map: HashMap<PackageId, CrateId> =
            HashMap::from_iter(metadata.packages.iter().map(|package| {
                (
                    package.id.clone(),
                    CrateId::from_package_id(&package.id.repr),
                )
            }));

        for (package, resolve_node) in metadata
            .packages
            .iter()
            .zip(metadata.resolve.as_ref().unwrap().nodes.iter())
        {
            // let package_name = package.name.clone().to_string();
            // let package_version = package.version.clone();
            let identifier = CrateId::from_package_id(&package.id.repr);
            if let Some(node_index) = tree_graph.node_index(&identifier) {
                let checksum = checksum_map.get(&identifier);
                self.components
                    .push(Component::create_component_from_cargo_data(
                        package,
                        resolve_node,
                        checksum,
                        &tree_graph,
                        *node_index,
                        &crate_identifier_map,
                    ));
            }
        }
    }

    pub fn write_to_file(&mut self, file_name: &str, output_dir: &Path, builder: &str) {
        let file_format = FileFormat::Json;
        let full_file_name = format!("{}_{}.raw.{}", file_name, builder, file_format);
        let mut file = match File::create(
            [output_dir, Path::new(&full_file_name)]
                .iter()
                .collect::<PathBuf>(),
        ) {
            Ok(file) => file,
            Err(e) => panic!("Could not create file: {}: {}", full_file_name, e),
        };

        self.bom_metadata.timestamp = generate_sbom_timestamp();

        file.write_all(serde_json::to_string(&self).unwrap().as_bytes())
            .expect("Could not write SBOM data to file.");
    }
}

pub fn write_sbom_to_file(
    sbom: &mut RawSbom,
    bom_format: &BomFormat,
    output_name: &str,
    output_dir: &Path,
    builder: &str,
) {
    match bom_format {
        BomFormat::Raw => sbom.write_to_file(output_name, output_dir, builder),
        BomFormat::SPDX => println!("No SPDX conversion currently"),
        BomFormat::CDX(CycloneDxSpecVersion::V1_6) => {
            CycloneDxSbomV1_6::convert_from_raw_and_write_to_file(
                sbom,
                output_name,
                output_dir,
                builder,
            )
        }
        BomFormat::CDX(CycloneDxSpecVersion::V1_7) => {
            CycloneDxSbomV1_7::convert_from_raw_and_write_to_file(
                sbom,
                output_name,
                output_dir,
                builder,
            )
        }
    }
}

pub fn generate_sbom_timestamp() -> Option<DateTime<Local>> {
    match env::var("TESTING_DETERMINISTIC") {
        Ok(value) if value == "1" => None,
        _ => Some(Local::now()),
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

impl FromStr for BomFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "raw" => Ok(BomFormat::Raw),
            "spdx" => Ok(BomFormat::SPDX),
            "cdx_1.6" | "cyclonedx_1.6" | "cyclone-dx_1.6" => {
                Ok(BomFormat::CDX(CycloneDxSpecVersion::V1_6))
            }
            "cdx_1.7" | "cyclonedx_1.7" | "cyclone-dx_1.7" => {
                Ok(BomFormat::CDX(CycloneDxSpecVersion::V1_7))
            }
            other => Err(format!("Invalid or unsupported BOM format: {}", other)),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum FileFormat {
    Json,
    Txt,
}

impl std::fmt::Display for FileFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            match self {
                FileFormat::Json => "json",
                FileFormat::Txt => "txt",
            }
        )
    }
}

impl FromStr for FileFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "json" => Ok(FileFormat::Json),
            other => Err(format!("Invalid or unsupported file format: {}", other)),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum CycloneDxSpecVersion {
    #[serde(rename = "1.6")]
    V1_6,

    #[serde(rename = "1.7")]
    V1_7,
}
