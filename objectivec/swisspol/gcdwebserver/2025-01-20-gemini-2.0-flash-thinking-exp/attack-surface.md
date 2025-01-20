# Attack Surface Analysis for swisspol/gcdwebserver

## Attack Surface: [Unauthenticated Access to Served Files](./attack_surfaces/unauthenticated_access_to_served_files.md)

* **Description:** `gcdwebserver` serves files from a specified directory without requiring any authentication by default.
    * **How gcdwebserver Contributes:** Its core function is to serve static files over HTTP. Without explicit configuration for authentication within the application using it, `gcdwebserver` inherently allows anyone who can reach the server to access these files.
    * **Example:** A developer configures `gcdwebserver` to serve files from the `/data` directory containing sensitive documents. Any user accessing `http://<server_ip>:<port>/confidential.pdf` will be able to download the file.
    * **Impact:** Exposure of sensitive data, confidential documents, or proprietary information.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Restrict Served Directory:**  Carefully choose the directory `gcdwebserver` serves from, ensuring it only contains truly public files. Avoid serving sensitive data directly.
        * **Place Behind an Authentication Layer:**  Deploy `gcdwebserver` behind a reverse proxy or within an application framework that handles authentication and authorization *before* requests reach `gcdwebserver`.

## Attack Surface: [Information Disclosure through Directory Listing (If Enabled)](./attack_surfaces/information_disclosure_through_directory_listing__if_enabled_.md)

* **Description:** If directory listing is enabled (or if no index file is present in a directory), `gcdwebserver` will display a list of files and subdirectories within that directory.
    * **How gcdwebserver Contributes:** This is a default behavior of `gcdwebserver` when an index file is not found in a requested directory.
    * **Example:** A user navigates to `http://<server_ip>:<port>/private/` and `gcdwebserver` displays a list of files like `budget.xlsx`, `passwords.txt`, etc., because no `index.html` exists in the `/private/` directory being served.
    * **Impact:**  Reveals the organization of files and the names of potentially sensitive files, aiding attackers in targeting specific resources.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Disable Directory Listing:** Configure `gcdwebserver` (if a configuration option exists) to explicitly disable directory listing.
        * **Ensure Index Files Exist:** Place an `index.html` (or similar) file in every directory served by `gcdwebserver` to prevent automatic directory listing.

