# Security review scope

This beta has focused code review and automated adversarial tests for private storage, malformed input, unsafe links, action revalidation, cancellation, UI contracts, scanner isolation and bounded network responses. It is not an independent audit or security certification.

The release excludes workstation reports and development evidence. Native build paths are anonymized before distribution. Runtime code, shipped dependencies and public documentation are reviewed separately from private development history.

Known limits include same-user/root compromise, incomplete asynchronous detection, upstream event loss, parser vulnerabilities, unsupported software inventory, incomplete native prevention acceptance and incomplete dependency/SBOM review. No fresh-machine or reboot acceptance is claimed. See [threat model](docs/THREAT_MODEL.md), [coverage](docs/DETECTION_COVERAGE.md) and [test results](TEST_RESULTS.md).
