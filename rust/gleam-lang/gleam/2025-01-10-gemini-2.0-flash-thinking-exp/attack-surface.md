# Attack Surface Analysis for gleam-lang/gleam

## Attack Surface: [Unsafe Foreign Function Interface (FFI) Calls to Erlang](./attack_surfaces/unsafe_foreign_function_interface__ffi__calls_to_erlang.md)

*   **Attack Surface:** Unsafe Foreign Function Interface (FFI) Calls to Erlang
    *   **Description:** Gleam allows calling arbitrary Erlang functions through its FFI. If Gleam code calls Erlang functions without proper input validation or understanding their security implications, it can introduce vulnerabilities.
    *   **How Gleam Contributes to the Attack Surface:** The `external fn` keyword in Gleam directly enables this interaction with Erlang code, making it a core feature that needs careful handling.
    *   **Example:** A Gleam application calls an Erlang function that executes shell commands based on user input without sanitization, leading to arbitrary command execution on the server.
    *   **Impact:** Critical - Can lead to arbitrary code execution, data breaches, system compromise, and denial of service.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Thoroughly vet Erlang functions called via FFI.
        *   Implement robust input validation and sanitization before passing data to Erlang functions.
        *   Create safe Gleam wrappers with built-in validation.
        *   Adhere to the principle of least privilege when calling Erlang functions.
        *   Conduct regular security audits of FFI usage.

## Attack Surface: [Security Vulnerabilities in Underlying Erlang/OTP](./attack_surfaces/security_vulnerabilities_in_underlying_erlangotp.md)

*   **Attack Surface:** Security Vulnerabilities in Underlying Erlang/OTP
    *   **Description:** Gleam applications rely on the Erlang/OTP platform. Any security vulnerabilities present in the Erlang virtual machine (BEAM), standard libraries, or concurrency primitives directly impact Gleam applications.
    *   **How Gleam Contributes to the Attack Surface:** Gleam inherently depends on Erlang/OTP, making it a foundational dependency that introduces potential vulnerabilities beyond Gleam's own codebase.
    *   **Example:** A known vulnerability in Erlang's SSL implementation could be exploited in a Gleam application using Erlang's `ssl` module for secure communication.
    *   **Impact:** High - Can range from denial of service and information disclosure to remote code execution, depending on the specific Erlang/OTP vulnerability.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Keep the Erlang/OTP installation updated with the latest security patches.
        *   Monitor Erlang/OTP security advisories.
        *   Utilize security scanning tools to identify known vulnerabilities in the Erlang/OTP runtime.

## Attack Surface: [Supply Chain Attacks on Gleam Dependencies](./attack_surfaces/supply_chain_attacks_on_gleam_dependencies.md)

*   **Attack Surface:** Supply Chain Attacks on Gleam Dependencies
    *   **Description:** Gleam projects rely on Hex packages for dependencies. Compromised or malicious dependencies introduced through the build process can inject malicious code into the final application.
    *   **How Gleam Contributes to the Attack Surface:** Gleam uses Hex as its package manager, making it susceptible to supply chain risks inherent in dependency management systems.
    *   **Example:** A malicious actor compromises a popular Gleam library on Hex and injects code that exfiltrates sensitive data from applications using that library.
    *   **Impact:** High - Can lead to data breaches, unauthorized access, and other significant security compromises.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Carefully review project dependencies and their maintainers.
        *   Use dependency lock files (e.g., `gleam.lock`) to ensure consistent dependency versions.
        *   Employ security scanning tools to identify vulnerabilities in project dependencies.
        *   Consider using private or internal package repositories for greater control over dependencies.

