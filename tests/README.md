## Introduction

This directory contains:

- tests for the tool (or only one right now), running on the examples of the [main repo](https://github.com/ariel-os/ariel-os)

- schematas to validate SBOM outputs against

Additionally, when running the test(s), if not present, the main branch of the main repo will be cloned here into the `./import` directory and `./output` will be created to store the SBOMs generated during the tests.

## Tests

### general-test

This test tests the tools functionality on the Ariel OS examples (just `coap-client` right now and on nRF52840-DK, no selection).

It does the following things:

- try to generate a CycloneDx 1.6 SBOM for the example

- validate whether the generated SBOM is a valid CycloneDx 1.6 SBOM

- compare the components from the final SBOM with the expected components based on `cargo tree`