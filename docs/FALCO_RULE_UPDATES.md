# Optional automatic Falco host rules

**Unreleased candidate:** the enable control is currently unavailable. A code-level
release gate also refuses enable/update calls, even with OS authentication. The
pinned downloader needs security fixes and privileged acceptance. The workflow
below describes the implemented opt-in design after those release gates pass.

This feature is **off by default**, including after installation or a plugin or
sensor update. Existing consent for ClamAV signatures does not enable it.
In Protection → Updates, the customer separately chooses **Enable Falco rule
updates…** and authenticates through the OS. The explanation states the download
schedule, additional host rules and brief monitoring restart. Monitoring must
already be enabled. The community feature remains free.

The root-owned timer checks the official `falco-rules:5` channel every six hours,
with up to fifteen minutes of jitter. The first scheduled check follows activation
by five to twenty minutes. Missed checks resume when the machine is available;
the timer does not wake or reboot it. Turning updates off disables future checks
and retains installed rules. Stopping monitoring prevents rule activation.
An in-progress activation is locked against explicit monitoring changes; a busy
change fails visibly and can be retried after the update finishes.

## Trust and activation

The optional sensor component includes falcoctl 0.14.2 from the already pinned
official Falco 0.45.1 archive. Its binary SHA-256 is
`6c51c056a9cb27f38acee7f20c91ccd6fea04710f529ea2eb253fff5822f10af`.
This hash establishes expected bytes, not independent provenance or absence of
vulnerabilities. Its native dependency and licensing closure still needs review.

Each update uses a fresh, disposable Bubblewrap filesystem and user namespace,
without the user's home, credentials, desktop sockets or host state. The worker
has network access for public registry and Sigstore verification. Its fixed local
index pins the official rules repository, GitHub Actions issuer and rules-workflow
identity; an upstream index cannot replace that trust policy. Signature and
transparency-log checks stay enabled. Dependency resolution is disabled and only
rulesfile artifacts are allowed: downloaded plugins and scripts are not executed.

The worker rejects unsupported YAML directives, aliases and oversized inputs.
It excludes container/plugin-dependent rules and their transitive macros, then
rewrites rule output to application name and event type. Existing eight Ironclad
rules remain. Falco compiles the combined rules in the isolated worker before any
activation. A compiler failure preserves the current generation.

Activation atomically selects a root-owned, hash-checked generation, briefly
restarts only Ironclad monitoring and checks fresh kernel/asynchronous metrics
and the selected generation's hash. Failure restores the previous selection and
restarts it. A transaction journal permits recovery after interruption; rollback
failure is reported rather than called success. No engine, kernel, OS package,
prevention mode, customer file or production website is updated by the timer.

## Coverage, privacy and limitations

The tested signed upstream snapshot produced 13 additional host rules; 12 disabled
or container-dependent rules were excluded. This count can change with accepted
updates. These are behavior detections, not ClamAV malware signatures, a complete
EDR platform, or a guarantee against new malware. False positives remain possible.
Compilation and fresh metrics do not measure detection accuracy. A broken rule
update can cause a brief monitoring gap even when rollback succeeds.

Rule names, time, application name, event type and severity enter the bounded local
alert feed. Command arguments, file paths, contents and raw Falco output are not
retained in it or uploaded. Rule downloads contact GHCR/GitHub and Sigstore public
services; no local alerts, files, package inventory or credentials are sent.
Falco still maintains internal process state as documented for existing monitoring.

The channel is constrained to major rule series 5. New requirements or incompatible
updates fail validation; changing the channel or downloader requires a reviewed
component update. This mechanism does not prevent a trusted publisher from shipping
a poor detection or replaying older signed content. Trust-root changes, freshness
failures, independent review, false-positive calibration and complete native
dependency auditing remain maintainer responsibilities. Previous generations are
retained locally for investigation; disabling does not delete them.

## Verification and release gates

Automated tests cover separate consent, disabled-update rejection, signature-policy
configuration, input filtering, alert redaction, identity checks, successful
activation and failed-health rollback using synthetic services. An actual signed
download and combined-rule compile succeeded inside an unprivileged namespace.
No customer timer is enabled by these tests.

Before broad release, test the privileged worker and timer, first enable/disable,
actual sensor activation and rollback, reboot recovery, uninstall, resource usage,
legitimate workloads and benign detection fixtures in an isolated Omarchy VM.
Do not describe mocked rollback tests as live-service acceptance. Keep the feature
off on customer machines until each customer explicitly opts in.

Official references: [Falco rule distribution](https://falco.org/docs/concepts/rules/default-custom/),
[signature verification](https://falco.org/blog/sign-verify-plugins-rules/),
[falcoctl](https://github.com/falcosecurity/falcoctl).
