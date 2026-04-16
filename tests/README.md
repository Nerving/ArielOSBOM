## Introduction

This directory contains:

- tests for the tool (or only one right now), running on the examples of the [main repo](https://github.com/ariel-os/ariel-os)

- the `fixtures` directory containing

    - a copy of the Ariel OS repository (not guaranteed to be most recent version of main branch)

    - schematas to validate SBOM outputs against

    - more to come if necessary

- an output directory that will be first generated when a test producing its own SBOM(s) is run

## Tests

### e2e

This test combines the following into one cohesive test:

- try to generate a CycloneDx 1.6 SBOM for the example

- validate whether the generated SBOM is a valid CycloneDx 1.6 SBOM

- compare the components from the final SBOM with the expected components based on `cargo tree`

Currently it does not support selection of Ariel OS examples or builders via arguments.