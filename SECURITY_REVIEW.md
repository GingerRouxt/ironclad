# Security review scope

This beta has focused code review and automated adversarial tests for private storage, malformed input, unsafe links, action revalidation, cancellation, UI contracts, scanner isolation and bounded network responses. It is not an independent audit or security certification.

The [post-launch review](docs/SUPPLY_CHAIN_REVIEW.md) adds a reproducible partial SBOM and dated advisory triage: two initial unsoundness matches were remediated in the rebuilt candidate, and three dependencies remain unmaintained. Independent native validation and maintenance migrations remain open; no complete dependency clearance is claimed. The proposed GUI change requires explicit AI action, and package removal refuses remaining diagnostic units. See [executed evidence](POST_LAUNCH_STATUS.md).

The release excludes workstation reports and development evidence. Native build paths are anonymized before distribution. Runtime code, shipped dependencies and public documentation are reviewed separately from private development history.

Known limits include same-user/root compromise, incomplete asynchronous detection, upstream event loss, parser vulnerabilities, unsupported software inventory, incomplete native prevention acceptance and incomplete dependency/SBOM review. No fresh-machine or reboot acceptance is claimed. See [threat model](docs/THREAT_MODEL.md), [coverage](docs/DETECTION_COVERAGE.md) and [test results](TEST_RESULTS.md).
