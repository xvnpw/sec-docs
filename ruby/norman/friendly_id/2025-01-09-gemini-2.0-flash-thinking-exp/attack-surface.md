# Attack Surface Analysis for norman/friendly_id

## Attack Surface: [SQL Injection via Slug Lookup](./attack_surfaces/sql_injection_via_slug_lookup.md)

**Description:**  Malicious SQL code is injected through the slug parameter when querying the database to find records.

**How FriendlyId Contributes:** FriendlyId uses slugs, often derived from user input, to identify records. If these slugs are not properly sanitized before being used in database queries, they become a vector for SQL injection.

**Example:** An attacker crafts a URL like `/posts/vulnerable' OR '1'='1`. If the application directly uses the slug value in a SQL query without parameterization, this could bypass authentication or retrieve unauthorized data.

**Impact:**  Full database compromise, data exfiltration, data manipulation, denial of service.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Use Parameterized Queries or ORM Features:**  Employ parameterized queries or the ORM's built-in find methods that automatically handle sanitization when querying by slug.
* **Avoid Direct String Interpolation in SQL:** Never directly embed the slug value into raw SQL queries.

## Attack Surface: [Predictable Slug Generation and Potential Authorization Bypass](./attack_surfaces/predictable_slug_generation_and_potential_authorization_bypass.md)

**Description:** The algorithm or pattern used to generate slugs is predictable, allowing attackers to guess valid slugs for resources they shouldn't access.

**How FriendlyId Contributes:** If the slug generation logic is simple or based on easily guessable patterns (e.g., sequential numbers, timestamps without sufficient randomness), it becomes easier for attackers to predict valid slugs.

**Example:** If slugs are generated sequentially like `resource-1`, `resource-2`, an attacker could try accessing `resource-3` even without knowing its actual link. If authorization solely relies on the presence of a valid slug, this could lead to unauthorized access.

**Impact:** Unauthorized access to resources, information disclosure, potential data manipulation if actions can be performed via predictable slugs.

**Risk Severity:** High

**Mitigation Strategies:**
* **Use More Complex and Random Slug Generation:** Employ algorithms that incorporate randomness or use UUIDs as part of the slug generation process.
* **Implement Robust Authorization Mechanisms:**  Don't rely solely on the presence of a valid slug for authorization. Implement proper authentication and authorization checks based on user roles and permissions.

## Attack Surface: [Code Injection via Custom Slug Generators](./attack_surfaces/code_injection_via_custom_slug_generators.md)

**Description:** If the application uses custom slug generators (via `slug_generator_class`) and user-provided data is directly incorporated into the generation logic without proper sanitization, it can lead to code injection.

**How FriendlyId Contributes:** FriendlyId allows for custom slug generation logic. If this custom code isn't carefully written and handles user input unsafely, it becomes a vulnerability.

**Example:** A custom slug generator might execute a shell command based on part of the input string used for the slug. An attacker could craft an input string that injects malicious commands.

**Impact:** Remote code execution, server compromise.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Thoroughly Review and Sanitize Input in Custom Slug Generators:** Treat any user-provided data used in custom slug generators as untrusted and sanitize it appropriately.
* **Avoid Dynamic Code Execution in Slug Generators:**  Refrain from using `eval()` or similar functions that execute arbitrary code based on user input.
* **Follow Secure Coding Practices:**  Apply general secure coding principles when developing custom slug generation logic.

