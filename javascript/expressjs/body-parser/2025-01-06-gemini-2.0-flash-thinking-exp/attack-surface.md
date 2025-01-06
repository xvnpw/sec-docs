# Attack Surface Analysis for expressjs/body-parser

## Attack Surface: [Excessive Payload Size leading to Denial of Service (DoS)](./attack_surfaces/excessive_payload_size_leading_to_denial_of_service__dos_.md)

* **Description:** An attacker sends an extremely large request body, overwhelming the server's resources (memory, CPU) and potentially causing it to crash or become unresponsive.
    * **How `body-parser` contributes:** `body-parser` parses the entire request body into memory. If the size is not limited via its configuration, it will attempt to process excessively large payloads.
    * **Example:** Sending a multi-gigabyte JSON payload to an endpoint expecting a small amount of data.
    * **Impact:** Service disruption, application unavailability, potential server crash.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Configure the `limit` option:** Set a reasonable maximum size for request bodies using the `limit` option in `body-parser`'s configuration.

## Attack Surface: [JSON Bomb/Zip Bomb leading to Resource Exhaustion](./attack_surfaces/json_bombzip_bomb_leading_to_resource_exhaustion.md)

* **Description:** An attacker sends a deceptively small JSON payload that expands exponentially upon parsing due to nested or recursive structures, leading to excessive memory consumption and potential DoS.
    * **How `body-parser` contributes:** The `json` parser in `body-parser` attempts to parse the entire JSON structure, including deeply nested objects or arrays, potentially triggering the expansion.
    * **Example:** Sending a JSON payload like `{"a": {"b": {"c": ...}}}` with hundreds or thousands of nested levels.
    * **Impact:** Server memory exhaustion, application crash, DoS.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Configure the `limit` option:** While not a complete solution, setting a `limit` can help prevent extremely large expansions.
        * **Use `strict: true` for JSON parsing:** This can help prevent parsing of certain malicious JSON structures.

## Attack Surface: [Unrestricted File Upload via Multipart Form Data](./attack_surfaces/unrestricted_file_upload_via_multipart_form_data.md)

* **Description:**  An attacker can upload arbitrary files to the server if the application doesn't properly validate file types, sizes, and contents after `body-parser` handles the multipart data.
    * **How `body-parser` contributes:** The `multer` middleware (or similar used with `body-parser`) parses the multipart form data and makes the uploaded files available. While `body-parser` itself doesn't perform validation, its configuration (or lack thereof) in handling multipart data is the initial step.
    * **Example:** Uploading an executable file to a server that only expects image files.
    * **Impact:** Remote code execution, data breaches, defacement, denial of service (by filling up disk space).
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Configure size limits for multipart uploads:** Use options within your multipart handling middleware (like `multer`'s `limits`) to restrict the size of uploaded files.

## Attack Surface: [Filename Manipulation leading to Path Traversal in Multipart Uploads](./attack_surfaces/filename_manipulation_leading_to_path_traversal_in_multipart_uploads.md)

* **Description:** An attacker crafts a malicious filename in the `Content-Disposition` header of a multipart request to write files to arbitrary locations on the server.
    * **How `body-parser` contributes:**  `body-parser` (or associated middleware like `multer`) extracts the filename from the `Content-Disposition` header. The application's subsequent use of this filename without sanitization creates the vulnerability, but `body-parser`'s parsing makes the filename available.
    * **Example:** Providing a filename like `../../../../evil.sh` in the `Content-Disposition` header.
    * **Impact:** Arbitrary file write, potential for remote code execution, data overwriting.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Avoid directly using user-provided filenames:**  Generate unique, server-controlled filenames for uploaded files instead of relying on the `Content-Disposition` header.

## Attack Surface: [Content-Type Sniffing Bypass in Multipart Uploads](./attack_surfaces/content-type_sniffing_bypass_in_multipart_uploads.md)

* **Description:** An attacker provides a misleading `Content-Type` header in a multipart request to bypass file type restrictions implemented by the application.
    * **How `body-parser` contributes:** `body-parser` parses the `Content-Type` header provided in the request. While the vulnerability lies in the application's reliance on this header, `body-parser` makes this header information accessible.
    * **Example:** Uploading an executable file but setting the `Content-Type` to `image/jpeg`.
    * **Impact:**  Uploading malicious files despite intended restrictions, potentially leading to remote code execution or other vulnerabilities.
    * **Risk Severity:** High
    * **Mitigation Strategies:**  *(Mitigation primarily happens *after* body-parser, but awareness of this attack vector is important when configuring multipart handling)*

## Attack Surface: [Resource Exhaustion via Large Raw Text or Binary Payloads](./attack_surfaces/resource_exhaustion_via_large_raw_text_or_binary_payloads.md)

* **Description:** Sending excessively large raw text or binary data in the request body can consume server resources, leading to DoS.
    * **How `body-parser` contributes:** The `text` and `raw` parsers in `body-parser` will attempt to read and process the entire payload into memory if not limited.
    * **Example:** Sending a multi-gigabyte text file as the request body.
    * **Impact:** Service disruption, application unavailability, potential server crash.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Configure the `limit` option:** Set a reasonable maximum size for raw text and binary request bodies using the `limit` option within the relevant `body-parser` middleware (e.g., `bodyParser.raw({ limit: '1mb' })`).

## Attack Surface: [Incorrect Configuration of `body-parser` Options](./attack_surfaces/incorrect_configuration_of__body-parser__options.md)

* **Description:**  Using insecure or default configurations of `body-parser` options can expose the application to vulnerabilities.
    * **How `body-parser` contributes:** The configuration directly dictates how `body-parser` processes requests. Incorrect settings directly lead to increased vulnerability.
    * **Example:** Not setting the `limit` option, disabling `inflate` without understanding the implications, or using insecure defaults.
    * **Impact:** Increased risk of DoS, exposure to other vulnerabilities depending on the misconfiguration.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Review and understand all configuration options:** Carefully review the documentation for all available options (`limit`, `inflate`, `strict`, `type`, etc.) and understand their security implications.
        * **Set appropriate limits:** Always set reasonable `limit` values for different content types.
        * **Enable `strict` mode for JSON parsing:** Use `strict: true` for JSON parsing to prevent parsing of certain potentially malicious structures.

