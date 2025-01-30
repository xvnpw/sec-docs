# Attack Surface Analysis for typicode/json-server

## Attack Surface: [Unauthenticated Data Access & Manipulation](./attack_surfaces/unauthenticated_data_access_&_manipulation.md)

### 1. Unauthenticated Data Access & Manipulation

*   **Description:**  Lack of built-in authentication and authorization allows anyone to access and modify data managed by `json-server`.
*   **json-server Contribution:** `json-server` by default exposes all RESTful endpoints (GET, POST, PUT, PATCH, DELETE) without requiring any authentication. This is inherent to its design as a rapid prototyping tool.
*   **Example:** An attacker can send a `DELETE` request to `/posts/1` and delete post with ID 1 without any credentials. Similarly, they can send a `POST` request to `/posts` to create new posts with arbitrary content, or `PUT/PATCH` to modify existing data.
*   **Impact:** Data breaches, data corruption, unauthorized data modification, complete compromise of data integrity.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Never expose `json-server` directly to the public internet in production environments.**
    *   **Implement a reverse proxy (e.g., Nginx, Apache) in front of `json-server` and enforce authentication and authorization at the proxy level before requests reach `json-server`.**
    *   **If integrating `json-server` programmatically, use middleware to implement authentication and authorization checks before requests are handled by `json-server`'s routing.**
    *   **For development and testing, restrict access to `json-server` to trusted networks or localhost only using firewall rules or network configurations.**

## Attack Surface: [Mass Assignment Vulnerability](./attack_surfaces/mass_assignment_vulnerability.md)

### 2. Mass Assignment Vulnerability

*   **Description:** Clients can modify any field of a resource by including them in PUT or PATCH requests, potentially altering fields they should not have access to or manipulating internal data structures unintentionally.
*   **json-server Contribution:** `json-server`'s default behavior is to accept and apply all fields present in the request body to the corresponding resource in `db.json` without field-level access control or filtering.
*   **Example:** Imagine a `/users` resource with fields like `id`, `username`, `password`, and `isAdmin`. An attacker could send a `PATCH` request to `/users/1` with the body `{"isAdmin": true}` and potentially elevate their privileges if the application logic relies on the `isAdmin` field in `db.json`. They could also modify other fields unexpectedly.
*   **Impact:** Privilege escalation, data corruption, unauthorized modification of sensitive data, potential bypass of intended application logic.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Avoid storing sensitive or critical application state directly in `db.json` if using `json-server` in scenarios beyond isolated prototyping.**
    *   **Implement input validation and sanitization *before* requests reach `json-server`. Filter or ignore unexpected or unauthorized fields in PUT and PATCH requests at the application level or reverse proxy.**
    *   **Structure your `db.json` to minimize the impact of mass assignment. Avoid including sensitive or privileged data directly accessible through modifiable fields if possible.**
    *   **For production-like scenarios, replace `json-server` with a backend solution that offers proper data access control and field-level security.**

