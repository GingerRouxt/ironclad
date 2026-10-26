# Native dependency rebuild

The post-launch candidate updates only anyhow 1.0.102 → 1.0.103 and Tokio 1.52.2 → 1.53.3 in the Cargo lock. These are the patched versions for [RUSTSEC-2026-0190](https://rustsec.org/advisories/RUSTSEC-2026-0190.html) and [RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html). The bundled fork identity becomes `0.2.0-ironclad.2`; upstream KRSI remains 0.2.0. This is a candidate, not a replacement of the published 0.2.36 release.

## Build boundary

Use a disposable Linux x86_64 builder with no home directory, credentials, host sockets or privileged capabilities. Provision trusted compiler/linker tooling separately; this script does not create a sandbox. Resolve/fetch public dependencies in a separate preparation step, then disable network access for builds and tests. Never run third-party Cargo build scripts or procedural macros with access to the owner's session.

The recipe checks all four public source/archive hashes and the extracted upstream BPF digest. It applies the recorded source and loader patches with zero fuzz. Rust must report exactly `rustc 1.99.1 (58cf8f9c3 2026-10-13)`; an unexpected compiler fails. The build environment is allowlisted, with two Cargo jobs, a fixed epoch, private temporary HOME, and remapped source/cache/toolchain paths. Host executable hooks and registry credentials are not inherited. This is reproducibility hardening, not authentication of a compiler binary.

Inside the isolated builder, with the repository mounted read-only at `/recipe`, public input archives at `/inputs`, a credential-free Cargo cache at `/cargo`, and the pinned toolchain at `/toolchain`:

```sh
python /recipe/tools/build_krsi_component.py \
  --work-dir /build/native --inputs /inputs --cargo-home /cargo \
  --toolchain-dir /toolchain --output /build/candidate.tar.gz
```

Repeat in a second empty builder using the **same canonical mount/work paths**, retain both outputs outside those builders, then compare with `cmp`. Different absolute build paths produced different native bytes despite remapped embedded source strings; arbitrary-path reproducibility is not claimed. Use the same linker/system inputs as well as the pinned Rust compiler.

No `--allow-network` is used for these builds. Set a memory limit and an overall timeout outside the script; the recipe also limits its build subprocess to 600 seconds. Run `cargo test --locked --offline -p krsi --lib` with the same toolchain, source and `IRONCLAD_UPSTREAM_BPF` environment. Matching canonical-path clean rebuilds were verified locally; builds at different work paths did not match. The upstream `load_and_attach_programs` test is ignored and is not covered by unprivileged unit tests. Never enable it on a working desktop merely to increase a test count.

Bundle, lock, embedded build-info, policy hashes and SBOM must change together. Run publication privacy checks over the nested native archive and retain the exact predecessor package before any authorized native update. A matching rebuild using the same tools is not independent reproducibility, signature verification or proof of safe kernel behavior.

## Maintenance findings

The resolved KRSI normal/build graph includes bincode 2.0.1 and paste 1.0.15. Bincode serializes and deserializes the local asynchronous event format; replacing it requires wire-format compatibility tests. Paste expands macros at build time. Both have unmaintained advisories, not a demonstrated application exploit in this review.

Proc-macro-error 1.0.4 remains in the workspace lock through aya-ebpf-macros. It is absent from the `cargo tree --locked --offline -p krsi -e normal,build` graph for this userspace-library build. The recipe reuses the pinned upstream BPF program rather than recompiling that workspace member. This narrows its relevance to this build; it does not clear the provenance or dependencies of the prebuilt upstream BPF bytes.

The reviewed Aya perf-buffer adapter uses Tokio AsyncFd. No direct `downcast_mut` call was found in the patched KRSI/SDK source search. Neither observation establishes full application reachability or immunity; the candidate updates both dependencies rather than relying on those searches to suppress the advisories. Complete Falco/system dependency and license closure still requires review.
