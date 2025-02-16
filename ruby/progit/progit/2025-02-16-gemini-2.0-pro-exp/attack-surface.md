# Attack Surface Analysis for progit/progit

## Attack Surface: [Command Injection](./attack_surfaces/command_injection.md)

**Description:** Execution of arbitrary Git commands or shell commands on the server due to insufficient validation of user input or improper handling of example commands from the `progit` book.

**How `progit` Contributes:** The book contains numerous Git command examples, which, if directly executable or used in string construction without sanitization, become *direct* injection points. This is the core of the direct risk.

**Example:**
    *   Application feature: "Try this command" allows users to execute Git commands *taken directly from the book's examples*.
    *   Attacker input: Modifies the displayed command (even slightly) to include malicious code, exploiting the application's trust in the book's content.  For example, adding a semicolon and a shell command: `git log; rm -rf /`

**Impact:** Complete server compromise, data loss, data modification, denial of service, potential lateral movement within the network.

**Risk Severity:** Critical

**Mitigation Strategies:**
    1.  **Absolutely never** execute Git commands directly based on user input, *nor directly from the book's examples without rigorous sanitization and validation*.
    2.  If interactive examples are *essential*, use a highly restricted, sandboxed environment with *extremely* limited privileges (e.g., a container with no network access and read-only access to a temporary, isolated Git repository).  The sandbox must prevent *any* interaction with the host system.
    3.  **Strongly prefer** client-side execution using WebAssembly-based Git implementations (e.g., isomorphic-git) to completely isolate execution from the server. This eliminates the server-side command injection risk entirely.
    4.  If server-side execution is unavoidable (strongly discouraged), use a whitelist of allowed commands and arguments, *never* a blacklist.  Reject any input that doesn't strictly conform to the whitelist. The whitelist should be as restrictive as possible.
    5.  Implement robust input validation and sanitization, even for seemingly harmless parameters.  Use a dedicated library for parsing and validating Git commands, if available.  Assume *all* input is malicious.
    6.  Run the application with the least necessary privileges (Principle of Least Privilege).

## Attack Surface: [Cross-Site Scripting (XSS) - *Conditional High Risk*](./attack_surfaces/cross-site_scripting__xss__-_conditional_high_risk.md)

**Description:** Injection of malicious JavaScript, potentially triggered by rendering `progit` content without proper HTML escaping.  This is only *directly* related if the application dynamically incorporates user-modifiable data *into* the rendered book content.

**How `progit` Contributes:**  The risk is direct if user-provided content is *intermingled* with the book's content during rendering, and that combined content is not properly escaped.  If the book content is rendered statically and separately from user input, this is *not* a direct risk from `progit`.

**Example:**
    *   Application feature:  Allows users to add "annotations" or "notes" to specific sections of the book, and these annotations are displayed *inline* with the book text.
    *   Attacker input (in an annotation): `<script>alert('XSS')</script>`
    *   If the application renders the annotation *within* the book content without escaping, the script will execute.  This is a *direct* contribution because the user input is being placed *into* the `progit` content's rendering context.

**Impact:**  Theft of user cookies, session hijacking, defacement of the application, redirection to malicious websites, phishing attacks.

**Risk Severity:** High (Conditional - only if user input is directly mixed with book content during rendering)

**Mitigation Strategies:**
    1.  **Always** use a robust HTML escaping library (provided by your web framework or a dedicated library) when rendering *any* content, especially when combining user-generated content with the `progit` content.
    2.  Implement a strong Content Security Policy (CSP) to restrict the execution of scripts.
    3.  Use HTTP-only cookies.
    4.  Sanitize user input *before* storing it (defense in depth), in addition to escaping during rendering.  Consider using a Markdown sanitizer if annotations support Markdown.
    5.  If possible, render user annotations *separately* from the book content, in a distinct visual area, to reduce the risk of injection into the book's rendering context.

## Attack Surface: [Path Traversal - *Conditional High Risk*](./attack_surfaces/path_traversal_-_conditional_high_risk.md)

**Description:** Manipulation of file paths mentioned in the `progit` book to access files outside the intended directory. This is only *directly* related if the application uses file paths *from the book* in a way that allows user influence.

**How `progit` Contributes:** The risk is direct if the application uses file paths *taken directly from the book's examples* and allows user input to influence those paths, even indirectly.

**Example:**
    * Application feature: "Show example file" displays the content of a file mentioned in a specific chapter of the book. The file path is constructed based on the chapter and a user-selected file name (even if the selection is from a dropdown).
    * Attacker input: Manipulates the file name selection (e.g., through URL parameter tampering) to include `../` sequences: `../../etc/passwd`.

**Impact:** Exposure of sensitive system files, configuration files, source code.

**Risk Severity:** High (Conditional - only if the application uses file paths from the book and allows user influence)

**Mitigation Strategies:**
    1.  **Never** construct file paths directly from user input, *nor directly from the book's examples without rigorous validation*.
    2.  If the application needs to display files mentioned in the book, use a *pre-defined, hardcoded mapping* of book sections to safe, internal file representations (e.g., IDs or keys). *Do not* allow the user to influence the file path in any way.
    3.  If direct file paths *must* be used (strongly discouraged), normalize them (remove `../` and similar sequences) and validate them against a strict whitelist *after* normalization. The whitelist should contain only the absolute paths of the files that are safe to display.
    4.  Run the application with the least necessary privileges.
    5.  Use a chroot jail or containerization to further restrict file system access.

