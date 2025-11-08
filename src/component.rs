use cargo_lock::Checksum;
use cargo_metadata::{Package};
use semver::{Version};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub id: String,
    pub build: bool
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Component {

    pub name: String,
    source: ComponentSource,
    pub id: String,
    pub version: Version,
    pub creators: Vec<String>, // TODO: enhance authors
    pub filename: Option<String>,
    pub licenses: Option<String>, // more specified later
    pub identifiers: Vec<String>, // more specified later for Hash, SWHID, ...
    pub executable_property: Option<bool>,
    pub archive_property: Option<bool>,
    pub structured_property: Option<bool>,

    pub uri_source_code: Option<String>,
    pub hash_source_code: Option<String>,
    pub uri_deployable_form: Option<String>,
    pub url_security_text: Option<String>,

    pub whatever_additional_temp: Vec<String>,

    // dependencies to be simply stored as index references into the packages
    // whether it's in the executable or build related (or if everything used: completely out of scope?)
        // not used right now
    pub dependencies: Vec<Dependency>,
}

impl Component {

    // bunch of stuff not yet addressed, for future
    pub fn create_component_from_metadata(package: &Package, hash: Option<&Checksum>, dependencies: Vec<Dependency>) -> Component {
        Component {
            source: ComponentSource::CargoMetadata,
            // maybe make more unique package ID later
            id: package.id.repr.clone(),
            name: package.name.to_string(),
            version: package.version.clone(),
            creators: package.authors.clone(),
            filename: None,
            licenses: package.license.clone(),
            identifiers: match hash {
                Some(hash) => vec![hash.to_string()],
                None => vec![],
            },

            executable_property: None,
            archive_property: None,
            structured_property: None,

            uri_source_code: package.repository.clone(),
            hash_source_code: None,
            uri_deployable_form: None,
            url_security_text: None,

            whatever_additional_temp: vec![],

            dependencies: dependencies,
        }
    }

}

// maybe Source instead per field basis?
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ComponentSource {
    CargoMetadata,
    CargoBloat, // 
    Other
}

//#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
//enum License {
//
//}