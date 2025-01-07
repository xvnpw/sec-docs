# Attack Surface Analysis for typicode/json-server

## Attack Surface: [Unrestricted Data Modification (CRUD Operations)](./attack_surfaces/unrestricted_data_modification__crud_operations_.md)

**Description:** The ability to create, read, update, and delete data without proper authorization or authentication.

**How json-server Contributes:** By default, `json-server` exposes all CRUD operations via RESTful endpoints without any built-in authentication or authorization. Anyone with network access can interact with the data.

**Example:** An attacker sends a `DELETE` request to `/posts/1` and successfully removes a critical blog post from the data store.

**Impact:** Data loss, data corruption, manipulation of application state, potential for denial of service by deleting essential data.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Implement robust authentication and authorization mechanisms *before* `json-server`. This could involve a reverse proxy or custom middleware that validates user credentials and permissions.
* Avoid using `json-server` directly in production environments without significant security hardening.
* If absolutely necessary to use in a controlled environment, limit network access to the `json-server` instance.

## Attack Surface: [Lack of Input Validation and Sanitization](./attack_surfaces/lack_of_input_validation_and_sanitization.md)

**Description:** The absence of checks and filtering on data submitted through API requests.

**How json-server Contributes:** `json-server` primarily reflects the data provided. It doesn't inherently validate or sanitize input, making it vulnerable to accepting malicious data.

**Example:** An attacker sends a `POST` request to `/posts` with a `title` field containing malicious JavaScript code. If this data is later displayed in a web application without proper escaping, it could lead to Cross-Site Scripting (XSS).

**Impact:** Stored Cross-Site Scripting (XSS), Server-Side Template Injection (if the data is used in server-side rendering), data integrity issues, potential for code injection in other parts of the application if the data is used without sanitization.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement input validation and sanitization on the client-side *and* the server-side (before `json-server` if possible, or in the application consuming the data).
* Use appropriate encoding and escaping techniques when displaying data retrieved from `json-server` in a web application.
* Define a strict schema for the data and validate incoming requests against it.

## Attack Surface: [Default Configuration Weaknesses](./attack_surfaces/default_configuration_weaknesses.md)

**Description:** The default settings of `json-server` are geared towards development and ease of use, not production security.

**How json-server Contributes:** By default, everything is open: no authentication, full CRUD access, no rate limiting, etc.

**Example:** Deploying a `json-server` instance with the default configuration directly to the internet exposes the entire data set to anyone.

**Impact:**  A wide range of impacts, including unauthorized data access, modification, and deletion, depending on the sensitivity of the data.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Never use the default configuration of `json-server` in a production environment.**
* Explicitly configure security measures like authentication, authorization, and rate limiting.
* Consider using the `--readOnly` flag for read-only APIs.

