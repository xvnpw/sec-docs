# Threat Model Analysis for facebook/relay

## Threat: [Fragment Injection](./threats/fragment_injection.md)

**Description:** An attacker might attempt to inject malicious GraphQL fragment definitions or manipulate the selection of fragments used by the application. This could occur if the application dynamically constructs or selects fragments based on user input or external data without proper sanitization. By injecting a malicious fragment, the attacker could force the application to fetch unauthorized data or potentially trigger unintended mutations.

**Impact:** Unauthorized data access, potential for data manipulation if injected fragments lead to mutations, application errors.

**Affected Relay Component:** `useFragment` hook, any custom logic for dynamic fragment composition or selection.

**Risk Severity:** High

**Mitigation Strategies:**
* Avoid dynamic fragment construction based on user input.
* If dynamic fragment selection is absolutely necessary, implement strict validation and sanitization of input to ensure it conforms to expected fragment names and structures.
* Utilize Relay's built-in mechanisms for fragment composition in a controlled manner.

## Threat: [Relay Compiler Vulnerabilities](./threats/relay_compiler_vulnerabilities.md)

**Description:** Vulnerabilities in the Relay Compiler itself could be exploited by an attacker who can influence the build process. This could involve injecting malicious code into the generated application artifacts or manipulating the compiler's behavior to introduce vulnerabilities.

**Impact:** Compromise of the application build process, potential for injecting malicious code into the final application.

**Affected Relay Component:** Relay Compiler.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Keep the Relay Compiler and its dependencies up-to-date with the latest security patches.
* Use trusted sources for Relay Compiler installation.
* Implement security scanning of the build environment and dependencies.

