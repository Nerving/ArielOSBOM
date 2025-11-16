This repository is for the WIP project for my bachelor's thesis (Comp. Sci., FU Berlin) under the guidance of [Prof. Dr. Emmanuel Baccelli](https://emmanuelbaccelli.com/). 

## Motivation and Goals

With increasing software supply chain attacks and security demands, Software Bills of Materials (SBOMs) have gained relevance in recent years. In the EU, the [Cyber Resilience Act (CRA)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj) will be requiring suppliers to draw up and if necessary provide SBOMs for their software. As a FOSS project, ArielOS itself technically does not fall under the CRA, however as seen with [RIOT e.g.](https://github.com/RIOT-OS/RIOT/pull/21530) demand can exist for users of ArielOS, so providing tooling to support with that makes sense. 

The goal of this project is to create/lay the groundwork for an SBOM generator for [Ariel OS](https://github.com/ariel-os/ariel-os) projects. Since the CRA does not go into much detail in terms of SBOM requirements, right now the current [BSI technical guideline for SBOMs](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf) will instead be used as a reference and compliance for it be strived towards.

## Current state

Kind of a first skeleton. Like other tools it only addresses Cargo related components so far. By using [cargo-bloat](https://crates.io/crates/cargo-bloat) to determine what actually lands in the final code, the amount of false positives can be reduced.

As of now the tool does the following:
- run cargo bloat with the latest laze build command to get info on crates/functions 
- run cargo metadata for info on all crates
- (if wanted) from cargo metadata filter only:
    - crates in the final executable
    - crates related to build dependencies of the crates represented in the executable
- take available relevant information from (filtered) cargo metadata
- write output to file, no SPDX/Cyclone-DX so far

## Usage

### Installation

- clone the repo and install [cargo-bloat](https://crates.io/crates/cargo-bloat)
- if not done already, install nightly toolchain: `rustup toolchain install nightly`

### Execution

- run the build process for which you want to generate the SBOM first (program takes latest command from ./builds/build-local.ninja) 
- only works using nightly toolchain right now (otherwise cargo metadata fails for ArielOS projects)
- provide the project's root path via the command line (`-r <PATH>`)

Current cli arguments:
```
    -r, --root-path     <PATH>              Path to project root [default: ./]
    -b, --bom-formats   <BOM_FORMAT>        BOM formats to generate [default: Raw] (only Raw so far, later SPDX and/or Cyclone-DX)
    -f, --file-format   <FILE_EXTENSION>    Data format of the generated SBOM [default: json] (only .json so far)
    -o, --output-name   <FILE_NAME>         File name of the generated SBOM [default: arielosbom]
        --bloat-filter  <BOOL>              Whether to generate and use cargo bloat data to filter cargo metadata [default: true]

    -m, --manifest-path <PATH>              (ignore)              
    -l, --lock-path     <PATH>              (ignore)
```

### Detailed

Installation:
- Clone the repo: 

`git clone https://github.com/Nerving/ArielOSBOM.git`
- Install cargo-bloat: 

`cargo install cargo-bloat`
- Install nightly toolchain and set it as default:

`rustup toolchain install nightly`, `rustup default nightly`


Execution:
- Run the build for which to create the SBOM (in your project directory):

`laze build -b <board>`
- Run ArielOSBOM (where the repo was cloned to) with your project root path as cli argument:

`cargo run -- -r <PATH> [other optional arguments, e.g. -o <FILE_NAME>]`

- The output file will be put into the ArielOSBOM root directory.

## To-Do / future considerations

- complete info for missing SBOM fields (and make it BSI compliant)
    - metadata: additional SPDX/Cyclone-DX specific information
    - provide output directly into at least one of SPDX/Cyclone-DX
    - determine which additional component identifiers (besides component hash) to use
- components
    - deal with non-Rust stuff (included binaries etc.)
    - more accurate Rust component recognition
        - analysis of build scripts for more accurate dependency results (less false positives)
        - correct/full cargo-bloat analysis
- extract and include ArielOS/domain specific relevant information
    - device specifications
    - storage/memory footprint
    - supported features/protocols
    - anything else?

- alternative data gathering in case cargo metadata fails
- some niceties:
    - generate for multiple devices, multiple BOM/file formats at once
- make the actual code nicer lol


## questions/whatever

For feedback of any sorts, I can be messaged on Matrix: @lekilian:matrix.org