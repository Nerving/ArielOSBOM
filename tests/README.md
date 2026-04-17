## Introduction

This directory contains:

- tests for the tool, running on the examples of the [main repo](https://github.com/ariel-os/ariel-os)

- the `fixtures` directory containing

    - a copy of the Ariel OS repository (not guaranteed to be most recent version of main branch)

    - schematas to validate SBOM outputs against

    - more to come if necessary

- an output directory that will be first generated when a test producing its own SBOM(s) is run

## Tests

Currently, all tests only use the CoAP example and the nrf52840dk builder.

### deterministic_generation

These tests check whether two separate calls of the tool generate identical SBOMs for each supported SBOM format (CycloneDX 1.6/1.7, Raw). 

Timestamps are omitted since these would introduce guaranteed differences in the SBOMs. For the CycloneDx formats, the `serialNumber` field is initialized to the crate [uuid](https://crates.io/crates/uuid)'s default value.

### e2e

This test serves as a general test for full program execution and validity checks. It combines the following into one cohesive test:

- try to generate a CycloneDx 1.6 SBOM for the example

- validate whether the generated SBOM is a valid CycloneDx 1.6 SBOM

- compare the components from the final SBOM with the expected components based on `cargo tree`