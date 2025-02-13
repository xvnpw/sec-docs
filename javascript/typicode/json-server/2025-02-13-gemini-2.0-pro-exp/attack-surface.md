# Attack Surface Analysis for typicode/json-server

## Attack Surface: [Unauthorized Data Modification (Default Behavior)](./attack_surfaces/unauthorized_data_modification__default_behavior_.md)

**Description:** Attackers can modify the data within the `db.json` file without any authentication.

**`json-server` Contribution:** `json-server` *defaults* to allowing unauthenticated `POST`, `PUT`, `PATCH`, and `DELETE` requests. This is its core design for rapid prototyping.

**Example:** An attacker sends a `POST` request to `/users` to add a new user with administrator privileges, or a `DELETE` request to `/products` to remove all product data.  They could also `PUT` or `PATCH` to alter existing data.

**Impact:** Data corruption, data loss, unauthorized access to other systems (if the added user has access elsewhere), complete system compromise (if combined with other vulnerabilities).

**Risk Severity:** **Critical**

**Mitigation Strategies:**

*   **Implement External Authentication:**  Use a reverse proxy (Nginx, Apache) or middleware in a Node.js application to handle authentication *before* requests reach `json-server`. Only forward authenticated requests.  This is *mandatory* for any non-trivial use.
*   **Implement Authorization:** After authentication, ensure the user has the *necessary permissions* to perform the requested action (e.g., only allow certain users to modify specific resources or fields).
*   **Use `--read-only` Flag:** If the data should be read-only, use the `--read-only` (or `-ro`) flag to prevent *any* modification requests. This is a simple but effective control for many scenarios.

## Attack Surface: [Unauthorized Data Disclosure (Default Behavior)](./attack_surfaces/unauthorized_data_disclosure__default_behavior_.md)

**Description:** Attackers can read all data exposed by `json-server` without any authentication.

**`json-server` Contribution:** `json-server` exposes the *entire contents* of the `db.json` file as a RESTful API *by default*.  There are no built-in access controls.

**Example:** An attacker sends a `GET` request to `/users` to retrieve all user data, including potentially sensitive information like email addresses, internal IDs, or any other data present in the file.

**Impact:** Data breach, privacy violation, potential for further attacks (e.g., using stolen information for phishing or credential stuffing).

**Risk Severity:** **Critical**

**Mitigation Strategies:**

*   **Data Sanitization:** Thoroughly review and remove *any* sensitive data from the `db.json` file *before* making the server accessible. This is a crucial preventative measure.
*   **Data Minimization:** Only include the *absolute minimum* data required for the application's functionality in the `db.json` file.  Adhere to the principle of least privilege.
*   **Implement External Authentication:** As with unauthorized modification, use a reverse proxy or middleware to require authentication for *all* requests. This is non-negotiable for sensitive data.

## Attack Surface: [Data Validation Bypass (Lack of Validation)](./attack_surfaces/data_validation_bypass__lack_of_validation_.md)

**Description:** Attackers can send arbitrary valid JSON data, bypassing any intended data validation and potentially injecting malicious payloads that could affect *consuming applications*.

**`json-server` Contribution:** `json-server` performs *no* data validation beyond basic JSON syntax checking. It accepts *any* structurally valid JSON, regardless of the data types or content.

**Example:** An attacker sends a `POST` request to `/products` where a `price` field (expected to be a number) contains a very long string, or a `description` field contains HTML/JavaScript (potentially leading to XSS if the consuming application doesn't sanitize the output).

**Impact:** Data corruption (within the `db.json` file), application instability (in the *consuming* application), potential for XSS or other injection attacks *in the consuming application*.  The impact is primarily on the *client* of the `json-server` API, not `json-server` itself.

**Risk Severity:** **High**

**Mitigation Strategies:**

*   **Implement External Input Validation:** Use a reverse proxy or middleware to validate *all* incoming data against a strict schema *before* it reaches `json-server`. Reject any requests that don't conform to the expected data types and constraints. This is crucial for preventing data corruption and mitigating injection risks.
*   **Client-Side Sanitization:**  The application *consuming* the data from `json-server` *must* also perform thorough input sanitization and output encoding to prevent XSS and other client-side vulnerabilities. This is a defense-in-depth measure.

