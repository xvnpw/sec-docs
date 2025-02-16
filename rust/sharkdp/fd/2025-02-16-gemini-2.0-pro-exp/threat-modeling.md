# Threat Model Analysis for sharkdp/fd

## Threat: [Path Traversal via Unsanitized Input to `fd`'s Search Path](./threats/path_traversal_via_unsanitized_input_to__fd_'s_search_path.md)

*   **Threat:** Path Traversal via Unsanitized Input to `fd`'s Search Path

    *   **Description:** An attacker provides input containing directory traversal sequences (e.g., `../`, `..\`, or absolute paths) that are directly used to construct the search path argument for `fd`. The attacker aims to escape the intended search directory and access files outside of the authorized area. They might use URL encoding or other techniques to bypass simple string filters.
    *   **Impact:** Information disclosure of sensitive files, potentially leading to credential theft, configuration exposure, or access to other restricted data. In some cases, this could lead to code execution if the attacker can access and execute malicious scripts.
    *   **`fd` Component Affected:** The core search functionality of `fd`, specifically how it interprets and processes the provided search path (the first positional argument, typically). This affects the path resolution logic within `fd`.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Whitelisting:** Define a whitelist of allowed search paths. Reject any input that does not match a pre-approved path.
        *   **Input Canonicalization:** Before passing the path to `fd`, use a robust library function to canonicalize the path, resolving all symbolic links, relative path components (`..`, `.`), and ensuring it's an absolute path within the allowed root directory.
        *   **Input Validation (Beyond Simple String Matching):** Use a dedicated path validation library that understands filesystem semantics, not just simple string matching. This library should handle URL encoding, different path separators, and other potential bypass techniques.
        *   **Chroot Jail/Containerization:** Confine the application (and thus `fd`) to a restricted filesystem subtree, making it impossible to traverse outside of that subtree.

## Threat: [Regular Expression Denial of Service (ReDoS) via Malicious Pattern Input](./threats/regular_expression_denial_of_service__redos__via_malicious_pattern_input.md)

*   **Threat:** Regular Expression Denial of Service (ReDoS) via Malicious Pattern Input

    *   **Description:** An attacker provides a crafted regular expression (or glob pattern, which `fd` converts to a regex) that causes `fd`'s regex engine to consume excessive CPU time and potentially memory. This is due to "catastrophic backtracking" in the regex engine.
    *   **Impact:** Denial of service (DoS). The application becomes unresponsive or crashes, preventing legitimate users from accessing it.
    *   **`fd` Component Affected:** The regular expression matching engine within `fd` (likely the `regex` crate in Rust). This affects the pattern parsing and matching logic.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Regex Complexity Limits:** Impose limits on the complexity of user-supplied regular expressions. This can involve limiting the length of the regex, the number of quantifiers (`*`, `+`, `?`, `{n,m}`), and the nesting depth.
        *   **Regex Engine Timeout:** Configure the regex engine (if possible) to have a timeout. If a regex takes too long to match, terminate the operation.
        *   **Use Simpler Matching (Glob):** If possible, encourage users to use glob patterns instead of full regular expressions. Glob patterns are generally less susceptible to ReDoS. `fd`'s globbing is usually safer, but still validate.
        *   **Regex Sanitization/Rewriting:** Attempt to sanitize or rewrite user-supplied regexes to remove potentially dangerous constructs. This is a complex and potentially error-prone approach.
        *   **Alternative Regex Engine:** Consider using a different regex engine that is known to be resistant to ReDoS (e.g., RE2). This would require modifying `fd`'s source code.

## Threat: [Information Disclosure via Symlink Following](./threats/information_disclosure_via_symlink_following.md)

*   **Threat:** Information Disclosure via Symlink Following

    *   **Description:** If `fd` is configured to follow symbolic links (`-L` or `--follow`), an attacker might create symbolic links that point to sensitive files or directories outside the intended search area. When `fd` traverses these symlinks, it could expose the target files.
    *   **Impact:** Information disclosure, similar to path traversal. The attacker gains access to files they should not be able to see.
    *   **`fd` Component Affected:** The symlink handling logic within `fd`. This affects how `fd` traverses the filesystem when encountering symbolic links.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Disable Symlink Following:** If following symlinks is not essential, disable it using the `--no-follow` option (or avoid using `-L`). This is the most secure option.
        *   **Careful Symlink Target Validation:** If symlink following is required, *before* following a symlink, rigorously validate the target path to ensure it's within the allowed search area. This requires canonicalizing the target path *after* resolving the symlink.
        *   **Chroot Jail/Containerization:** Even if symlinks are followed, a chroot jail or container will limit the accessible filesystem, reducing the impact.

## Threat: [Binary Tampering of `fd` executable](./threats/binary_tampering_of__fd__executable.md)

* **Threat:** Binary Tampering of `fd` executable

    * **Description:** An attacker with write access to the `fd` binary replaces it with a malicious version. This malicious version could return fabricated search results, execute arbitrary code, or leak data.
    * **Impact:** Complete system compromise. The attacker can control the results of file searches and potentially execute arbitrary code with the privileges of the application.
    * **`fd` Component Affected:** The entire `fd` executable.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **File Integrity Monitoring (FIM):** Use a FIM system to detect any unauthorized changes to the `fd` binary.
        * **Digital Signatures:** If available, use a digitally signed version of `fd` and verify the signature before execution.
        * **Read-Only Filesystem:** Mount the directory containing the `fd` binary as read-only, if possible.
        * **Least Privilege:** Run the application with the lowest possible privileges.

