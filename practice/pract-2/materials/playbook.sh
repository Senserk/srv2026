#!/usr/bin/env bash
set -euo pipefail

# Student playbook. This file is available in the container as /work/playbook.sh.
# Copy the commands from the guide into the corresponding TODO sections.

cd /work/repository

baseline() {
  # TODO 1: Build the project and run the functional test.
  :
}

scan_sast() {
  # TODO 2: Run Clang Static Analyzer.
  :
}

scan_dast() {
  # TODO 3: Build with AddressSanitizer and run the program on several inputs.
  :
}

scan_secrets() {
  # TODO 4: Scan the working tree and the complete Git history.
  :
}

build_release() {
  # TODO 5: Build the practice-2-release:student image.
  :
}

make_sbom() {
  # TODO 6: Create /work/reports/sbom.cdx.json.
  :
}

scan_dependencies() {
  # TODO 7: Scan the SBOM with Grype.
  :
}

scan_container() {
  # TODO 8: Scan Dockerfile and compose.yaml with Trivy.
  :
}

verify_release() {
  # TODO 9: Repeat all checks and run the automated gate.
  :
}

case "${1:-}" in
  baseline|scan_sast|scan_dast|scan_secrets|build_release|make_sbom|scan_dependencies|scan_container|verify_release)
    "$1"
    ;;
  *)
    echo "Stages: baseline scan_sast scan_dast scan_secrets build_release make_sbom scan_dependencies scan_container verify_release"
    exit 2
    ;;
esac
