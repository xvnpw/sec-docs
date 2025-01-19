# Attack Surface Analysis for jgm/pandoc

## Attack Surface: [Maliciously Crafted Input Files Exploiting Parser Vulnerabilities](./attack_surfaces/maliciously_crafted_input_files_exploiting_parser_vulnerabilities.md)

*   **Description:**  Providing Pandoc with specially crafted input files designed to trigger vulnerabilities within its parsing libraries.
    *   **How Pandoc Contributes:** Pandoc relies on various parsers to handle a wide range of input formats. Vulnerabilities in *these parsers within Pandoc* can be exploited.
    *   **Example:**  Submitting a DOCX file with a malformed structure that causes a buffer overflow in the underlying XML parsing library *used by Pandoc*.
    *   **Impact:** Denial of Service (DoS), potential for arbitrary code execution on the server if the vulnerability is severe enough.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Strict input validation and sanitization of all data passed to Pandoc.
        *   Run Pandoc in a sandboxed environment with limited resource access.
        *   Keep Pandoc updated to patch known vulnerabilities in its core and bundled libraries.
        *   Consider limiting the allowed input formats to only those strictly necessary.

## Attack Surface: [Command Injection via Filters or External Programs](./attack_surfaces/command_injection_via_filters_or_external_programs.md)

*   **Description:**  Exploiting Pandoc's ability to use external filters or programs for conversion by injecting malicious commands.
    *   **How Pandoc Contributes:** Pandoc allows specifying external programs or scripts (filters) to process documents. If user input influences these specifications, it can lead to command injection.
    *   **Example:**  A user provides input that is used to construct a Pandoc command line including a malicious filter: `pandoc input.md --filter "evil_script.sh && rm -rf /" -o output.pdf`.
    *   **Impact:** Arbitrary code execution on the server, potentially leading to complete system compromise.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Avoid allowing user input to directly control or influence the filters or external programs used by Pandoc.
        *   If filters are necessary, use a predefined and tightly controlled set of filters.
        *   Sanitize any user-provided data that might be used in filter arguments.
        *   Run Pandoc with minimal privileges.
        *   Consider using Pandoc's Lua filtering capabilities with strict security reviews of the Lua scripts.

## Attack Surface: [Server-Side Request Forgery (SSRF) via External Resource Fetching](./attack_surfaces/server-side_request_forgery__ssrf__via_external_resource_fetching.md)

*   **Description:**  Tricking Pandoc into making requests to internal or external resources that the attacker shouldn't have access to.
    *   **How Pandoc Contributes:** Pandoc can fetch external resources like images or stylesheets if specified in the input document or through command-line options.
    *   **Example:**  An attacker provides a Markdown document with an image link pointing to an internal service: `![Internal Service](http://internal.server/sensitive_data)`. When Pandoc processes this, it makes a request to the internal service.
    *   **Impact:** Access to internal resources, potential data leakage, port scanning of internal networks.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Disable or restrict Pandoc's ability to fetch external resources.
        *   If external resource fetching is necessary, implement a strict allowlist of allowed domains or protocols.
        *   Sanitize and validate URLs provided in input documents.
        *   Run Pandoc in a network environment with appropriate firewall rules.

