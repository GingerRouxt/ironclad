# Rules-only downloader build and audit

The bundled component is falcoctl **0.14.2-ironclad.1**, based on upstream v0.14.2.
It is a separately identified fork, not an upstream release or signed provenance
attestation. The optional sensor package verifies both archive and binary hashes.

| Input/result | Pin |
|---|---|
| Source | `https://codeload.github.com/falcosecurity/falcoctl/tar.gz/refs/tags/v0.14.2` |
| Source SHA-256 | `2ac3bd90913933e7fb6f9a722e1b8999dedaaab158c1ea073405d28c491112c1` |
| Toolchain | Go 1.27.3, Linux x86_64, CGO disabled |
| Binary SHA-256 | `8ac0c07b90e4a437d4f44b8a360c3f6a91ae560706aea8b41627caf7019e5918` |
| Archive SHA-256 | `46b2e864cfe54cb9202b41a67f295606ec6899d0262d42019f4e08f1991048a6` |

`tools/falcoctl-rules-only.patch`, `tools/falcoctl-go.mod` and
`tools/falcoctl-go.sum` are the reviewed build inputs. The recipe applies only
that repository-owned patch, downloads Go modules only when explicitly requested,
and compiles twice without network access or host home/credentials. No upstream
setup scripts or `go generate` run. Symbol information is retained for binary
vulnerability analysis; DWARF and build IDs are omitted. The two local builds
matched byte-for-byte. This is local repeatability, not independent reproduction.

From this repository, after downloading and checking the source archive:

```sh
mise install go@1.27.3
mise exec -- uv run python tools/build_falcoctl_component.py \
  --source-archive /path/to/falcoctl-v0.14.2.tar.gz \
  --work-directory /path/to/new-private-build-directory \
  --go-directory "$(mise where go@1.27.3)" \
  --fetch-dependencies \
  --output /path/to/falcoctl-component.tar.gz
```

Review the patch and locked dependencies first. Use an empty source destination;
existing caches may be reused, but the recipe refuses to overwrite an existing
source directory. `--fetch-dependencies` contacts public Go module services from
an isolated environment. Builds themselves use `GOPROXY=off`, `GOSUMDB=off`,
`-mod=readonly` and an allowlisted environment. `go mod verify` checks cached bytes.
The artifact includes the Go toolchain license, notices from all 159 modules
recorded by `go version -m`, and source/lock/patch hashes. The SBOM reproduces that
module inventory, including resolved replacements, and rejects provenance drift.
It does not equate a recorded module with a reachable vulnerable function.

## Dated advisory result: October 26, 2026 UTC

`govulncheck@v1.9.0` source analysis of the reduced main package and binary analysis
of the exact bundled executable both reported **zero affected symbols and zero
vulnerable imported packages**. Both retained one module-level advisory:
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), concerning the obsolete
`golang.org/x/crypto/openpgp` packages. Those packages are not imported by this
build. Updated Rekor uses the maintained ProtonMail implementation instead.
The `x/crypto` module remains for other algorithms. Do not suppress or describe
that module match as a completely clean dependency inventory.

The former Go standard-library, x/net, chi and OpenTelemetry version matches were
addressed by updates; the old ACR credential helper is no longer in the linked
module inventory. Early stripped-binary scans conservatively reported packages
from module metadata; the shipped build retains symbols and was rescanned.
Historical failed builds and scans remain private evidence, not passing checks.

The reduced adapter uses Cosign's own cryptographic and artifact-claim verifiers.
It rejects missing policy, insecure transport, unsigned operation, alternate
repositories and credential-based paths. Both v3 in-toto and legacy simple claims
must bind to the exact pulled digest. Live signed-download and negative-policy
checks are separate from the vulnerability scan. None of these checks is a
security certification, comprehensive license opinion or guarantee against new
vulnerabilities. Re-run them for every component change.
