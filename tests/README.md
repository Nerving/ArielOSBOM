## Introduction

This directory contains:

- tests for the tool, running on the examples of the [main repo](https://github.com/ariel-os/ariel-os)

- the `fixtures` directory containing

    - a copy of the Ariel OS repository (not guaranteed to be most recent version of main branch)

    - schematas to validate SBOM outputs against

    - more to come if necessary

- an output directory that will be first generated when a test producing its own SBOM(s) is run

## Tests

Currently, all tests only use the CoAP example and the nrf52840dk builder unless otherwise specified.

### board_specific_components

These tests check for boards of different kinds whether an SBOM generated for the board contains the expected board-family components.

The current tests include and check for:

- esp boards (espressif-esp32-c6-devkitc-1): `ariel-os-esp`, `esp-alloc`, `esp-bootloader-esp-idf`, `esp-config`, `esp-hal`, `esp-hal-procmacros`, `esp-metadata-generated`, `esp-println`, `esp-riscv-rt`, `esp-rom-sys`, `esp-sync` 

- nrf boards (nrf52840dk): `ariel-os-nrf`, `embassy-nrf`, `nrf-pac`

- rp boards (rpi-pico): `ariel-os-rp`, `embassy-rp`, `rp-pac`, `rp2040-boot2`

- stm32 boards (stm32u083c-dk): `ariel-os-stm32`, `ariel-os-stm32-mapping`, `embassy-stm32`, `stm32-fmc`, `stm32-metapac`

Right now these are only tests for general crates shared amongst these four board families, on a single example for a single builder of the respective board family(thermometer for stm32).

### deterministic_generation

These tests check whether two separate calls of the tool generate identical SBOMs for each supported SBOM format (CycloneDX 1.6/1.7, Raw). 

Timestamps are omitted since these would introduce guaranteed differences in the SBOMs. For the CycloneDx formats, the `serialNumber` field is initialized to the crate [uuid](https://crates.io/crates/uuid)'s default value.

### e2e

These tests serve as a general test for full program execution and validity checks for both a main repo example and an out-of-tree recration of the coap-client example. Right now they combine the following into one cohesive test:

- try to generate a CycloneDx 1.6 SBOM for the example

- validate whether the generated SBOM is a valid CycloneDx 1.6 SBOM

- compare the components from the final SBOM with the expected components based on `cargo tree`

Note that the execution `e2e_out_of_tree` tends to take a noticeable bit longer than the example runs during dependency resolution.

### feature_resolution

These tests verify that the `--features` argument parsed from laze's build command is properly propagated by comparing the tool's generated `cargo tree` component set against one from the output of a direct invocation of `cargo tree`.

The tests currently include:

- a baseline test with all features from laze's build command

- one test where each respective feature has been removed from the list of features

- one test where all features provided via `--features` have been removed