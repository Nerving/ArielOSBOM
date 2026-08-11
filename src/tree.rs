use std::{collections::HashMap, fs::File, io::Write, path::Path, process::Command};

use crate::{ArielOsBuildContext, CrateId, sbom::FileFormat};

pub struct CargoTreeGraph {
    pub nodes: Vec<CrateId>,
    pub dependencies: Vec<Vec<TreeDependency>>,
    node_index_map: HashMap<CrateId, usize>,
}

impl CargoTreeGraph {
    pub fn node_index(&self, node: &CrateId) -> Option<&usize> {
        self.node_index_map.get(node)
    }

    // pub fn node_identifier(&self, node_index: usize) -> Option<&CrateIdentifier> {
    //     if node_index >= self.nodes.len() {
    //         None
    //     } else {
    //         Some(self.nodes[node_index].identifier())
    //     }
    // }
}

// pub struct TreeNode {
//     identifier: CrateIdentifier,
//     _source: Option<String>,
// }

// impl TreeNode {
//     pub fn identifier(&self) -> &CrateIdentifier {
//         &self.identifier
//     }

//     pub fn name(&self) -> &str {
//         self.identifier.name()
//     }
// }

#[derive(Debug)]
pub struct TreeDependency {
    pub node_index: usize,
    pub is_proc_macro: bool,
    pub dependency_kind: DependencyKind,
}

impl TreeDependency {
    pub fn is_build(&self) -> bool {
        self.dependency_kind.is_build()
    }

    pub fn is_normal(&self) -> bool {
        self.dependency_kind.is_normal()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DependencyKind {
    Normal,
    BuildDependency,
}

impl DependencyKind {
    fn is_build(&self) -> bool {
        matches!(self, DependencyKind::BuildDependency)
    }

    fn is_normal(&self) -> bool {
        matches!(self, DependencyKind::Normal)
    }
}

type DepthStack = Vec<DepthStackEntry>;

#[derive(Clone, Debug)]
struct DepthStackEntry {
    node_index: usize,
    dependency_kind_state: DependencyKind,
}

impl DepthStackEntry {
    fn new(node_index: usize) -> DepthStackEntry {
        DepthStackEntry {
            node_index,
            dependency_kind_state: DependencyKind::Normal,
        }
    }
}

pub fn generate_cargo_tree_output(context: &ArielOsBuildContext) -> Vec<u8> {
    let envs_key_value: Vec<(&str, &str)> = context
        .build_command
        .envs
        .iter()
        .map(|key_arg| key_arg.split_once('=').unwrap())
        .collect();

    Command::new("cargo")
        .envs(envs_key_value)
        .current_dir(&context.root_path)
        .arg("tree")
        .arg("--color")
        .arg("never")
        .arg("--edges")
        .arg("normal,build")
        .arg("--manifest-path")
        .arg(&context.manifest_path)
        .arg(&context.build_command.features)
        .output()
        .expect("Something failed with cargo tree")
        .stdout
}

pub fn parse_cargo_tree(tree_data: Vec<u8>) -> CargoTreeGraph {
    let tree_data =
        String::from_utf8(tree_data).expect("could not convert cargo tree output from UTF8 to str");

    let mut nodes: Vec<CrateId> = Vec::new();
    let mut dependencies: Vec<Vec<TreeDependency>> = Vec::new();
    let mut node_index_map: HashMap<CrateId, usize> = HashMap::new();
    let mut depth_stack: DepthStack = Vec::new();
    for tree_line in tree_data.lines() {
        let trimmed_line =
            tree_line.trim_start_matches(|c: char| [' ', '├', '│', '└', '─'].contains(&c));
        let depth = (tree_line.chars().count() - trimmed_line.chars().count()) / 4; // check if depth <= depth_stack.len()? otherwise error parsing

        if trimmed_line == "[build-dependencies]" {
            if depth != 0 {
                depth_stack[depth - 1].dependency_kind_state = DependencyKind::BuildDependency;
            }
            continue;
        }

        let (node, is_proc_macro) = CrateId::from_cargo_tree_line(trimmed_line);
        let node_index = *node_index_map.entry(node.clone()).or_insert_with(|| {
            nodes.push(node);
            dependencies.push(Vec::new());
            nodes.len() - 1
        });

        let depth_stack_entry = DepthStackEntry::new(node_index);
        if depth >= depth_stack.len() {
            depth_stack.push(depth_stack_entry);
        } else {
            depth_stack[depth] = depth_stack_entry;
        }

        if depth != 0 {
            dependencies[depth_stack[depth - 1].node_index].push(TreeDependency {
                node_index,
                is_proc_macro,
                dependency_kind: depth_stack[depth - 1].dependency_kind_state,
            });
        }
    }

    CargoTreeGraph {
        nodes,
        dependencies,
        node_index_map,
    }
}

// pub fn parse_tree_line(line: &str) -> (TreeNode, bool) {
//     let end_trimmed = line.trim_end_matches(" (*)");
//     let mut split_line = end_trimmed.split_whitespace();

//     //we are guaranteed to have name and version; would technically want to check for errors though
//     let identifier = CrateIdentifier::new(
//         split_line.next().unwrap().to_string(),
//         Version::from_str(&split_line.next().unwrap()[1..]).unwrap(),
//     );
//     let mut is_proc_macro = false;
//     let mut _source: Option<String> = None;
//     for part in split_line {
//         if part == "(proc-macro)" {
//             is_proc_macro = true;
//         } else {
//             // can't have anything else there afaik with the regular cargo tree call
//             _source = Some(part[1..part.len() - 1].to_string());
//         }
//     }

//     (
//         TreeNode {
//             identifier,
//             _source,
//         },
//         is_proc_macro,
//     )
// }

pub fn write_tree_to_file(tree: Vec<u8>, file_name: &str, output_dir: &Path, builder: &str) {
    let file_format = FileFormat::Txt;
    let full_file_name = format!("{}_{}.tree.{}", file_name, builder, file_format);
    let mut file = match File::create(Path::new(output_dir).join(&full_file_name)) {
        Ok(file) => file,
        Err(e) => panic!("Could not create file: {}: {}", full_file_name, e),
    };

    file.write_all(&tree)
        .expect("failed to write cargo tree to file");
}
