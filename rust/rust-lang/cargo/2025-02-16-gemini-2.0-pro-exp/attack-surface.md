# Attack Surface Analysis for rust-lang/cargo

## Attack Surface: [Malicious Crates (Supply Chain Attack)](./attack_surfaces/malicious_crates__supply_chain_attack_.md)

*   **Description:** An attacker publishes a malicious crate to a public or private registry, which is then included as a dependency in a project.
    *   **How Cargo Contributes:** Cargo is the *primary mechanism* for including external dependencies.  Its dependency resolution and fetching process are the direct attack vector.
    *   **Example:** A crate named `popular-utils` is published with a `build.rs` script that downloads and executes a malicious payload during the build process. A developer unknowingly adds `popular-utils` as a dependency.
    *   **Impact:** Code execution on the developer's machine or build server, data exfiltration, system compromise, potential lateral movement within a network.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **`cargo vet`:** Use `cargo vet` to audit and approve specific versions of dependencies.
        *   **`cargo-crev`:** Leverage community reviews of crates using `cargo-crev`.
        *   **`cargo audit`:** Regularly run `cargo audit` to check for known vulnerabilities.
        *   **Dependency Pinning:** Pin dependencies to specific versions in `Cargo.toml`.
        *   **Careful Dependency Selection:** Prioritize well-maintained, widely-used crates.
        *   **Source Code Review:** For critical dependencies, consider manual source code review.
        *   **Monitor for yanked crates:** Be aware of crates yanked from crates.io.

## Attack Surface: [Typosquatting](./attack_surfaces/typosquatting.md)

*   **Description:** An attacker publishes a crate with a name very similar to a popular crate, hoping developers will make a typo and install the malicious version.
    *   **How Cargo Contributes:** Cargo's reliance on textual crate names in `Cargo.toml`, and its handling of dependency resolution from `crates.io` (or other registries), are the direct enablers of this attack.
    *   **Example:** An attacker publishes a crate named `serd` (instead of `serde`), and a developer accidentally types the incorrect name.
    *   **Impact:** Similar to malicious crates: code execution, data exfiltration, system compromise.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Careful Typing and Review:** Double-check crate names in `Cargo.toml`.
        *   **Code Completion:** Use an IDE with Rust support and code completion.
        *   **`cargo add`:** Use `cargo add <crate_name>` for adding dependencies.

## Attack Surface: [Dependency Confusion](./attack_surfaces/dependency_confusion.md)

*   **Description:** An attacker publishes a malicious crate on a public registry with the same name as a private, internal crate.
    *   **How Cargo Contributes:** Cargo's dependency resolution logic, particularly its default behavior of searching `crates.io` and the configuration options for registries, are directly involved in this attack.  The vulnerability exists in how Cargo *chooses* which crate to download.
    *   **Example:** A company has a private crate named `internal-auth`. An attacker publishes a malicious `internal-auth` on `crates.io`. Misconfigured Cargo pulls the public version.
    *   **Impact:** Code execution, data exfiltration, compromise of internal systems.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Explicit Registry Configuration:** In `Cargo.toml` and `.cargo/config.toml`, explicitly specify the registry for *each* dependency.
        *   **Scoped Packages (Naming Convention):** Use a consistent naming convention for private crates.
        *   **Prioritize Registries:** *Carefully* configure Cargo to prioritize the private registry (with awareness of potential build failures).

## Attack Surface: [Malicious `build.rs`](./attack_surfaces/malicious__build_rs_.md)

*   **Description:** A crate includes a `build.rs` script that performs malicious actions during the build process.
    *   **How Cargo Contributes:** Cargo's feature of allowing crates to include and execute `build.rs` scripts is the *direct* enabler of this attack vector.  The build script runs with the user's privileges.
    *   **Example:** A crate's `build.rs` script connects to a remote server and uploads sensitive environment variables.
    *   **Impact:** Code execution, data exfiltration, system compromise, *before* main application code compilation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Review `build.rs`:** Carefully review the code of `build.rs` scripts.
        *   **Avoid Unnecessary `build.rs`:** Prefer crates without complex `build.rs` scripts.
        *   **Sandboxing (Advanced):** Explore (complex) sandboxing (requires custom tooling; Cargo doesn't provide this natively).

