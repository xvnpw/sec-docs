# Threat Model Analysis for thoughtbot/factory_bot

## Threat: [Leakage of Sensitive Data from Factory Definitions](./threats/leakage_of_sensitive_data_from_factory_definitions.md)

*   **Description:** An attacker gains access to the codebase (e.g., through a compromised developer account, a leaked repository, or a vulnerability in a code hosting platform). They examine the `factory_bot` factory definitions and find hardcoded sensitive data, such as default passwords, API keys, or predictable patterns for generating "dummy" data (like credit card numbers or social security numbers). The attacker then uses this information to craft attacks against the production system.
    *   **Impact:**
        *   Compromise of user accounts.
        *   Unauthorized access to sensitive data.
        *   Financial fraud.
        *   Reputational damage.
    *   **Affected Component:** Factory definitions (the Ruby files defining the factories, typically located in `spec/factories` or `test/factories`). Specifically, the attributes and their assigned values within the `factory` and `trait` blocks.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Dynamic Data Generation:** Use libraries like `Faker` to generate realistic but *random* data for sensitive fields.  Avoid *any* hardcoded sensitive values.  Example:  `password { Faker::Internet.password(min_length: 10, max_length: 20, mix_case: true, special_characters: true) }`
        *   **Code Reviews:**  Mandatory code reviews for all factory definitions, specifically looking for hardcoded sensitive data.
        *   **Secrets Management:**  If factories *must* use secrets (e.g., for testing interactions with external services), use a secure secrets management solution (e.g., environment variables, a dedicated secrets vault) and *never* store secrets directly in the factory definitions.
        *   **Regular Audits:**  Periodically audit all factory definitions for potential security issues.
        *   **.gitignore:** Ensure that any files containing sensitive test data (if they exist despite best practices) are explicitly excluded from version control using `.gitignore` (or equivalent).

## Threat: [Test-Induced Production Data Modification](./threats/test-induced_production_data_modification.md)

*   **Description:** An attacker with developer access (or through a compromised CI/CD pipeline that has *incorrectly configured access*) runs tests that use `factory_bot` against the *production* database. This is due to misconfiguration or a lack of understanding of the testing environment. The tests create, modify, or delete real user data. *Crucially, this threat assumes the CI/CD pipeline or developer machine is misconfigured to point at the production database*.
    *   **Impact:**
        *   Data loss or corruption.
        *   Service disruption.
        *   Violation of data privacy regulations.
        *   Legal and financial consequences.
    *   **Affected Component:** The entire `factory_bot` setup, in conjunction with the application's database configuration. The issue isn't a specific `factory_bot` component, but rather the *environment* in which it's used and the *incorrect configuration* allowing it to connect to production.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Environment Separation:** Enforce a clear separation between development, testing, staging, and production environments. Use *different* database credentials for *each* environment.  This is the primary defense.
        *   **Database Configuration Review:** Carefully review the database configuration files (e.g., `config/database.yml` in Rails) to ensure that the test environment *explicitly* points to a dedicated test database.
        *   **Database Cleaning:** Use a database cleaning strategy (e.g., `database_cleaner` gem) to automatically reset the test database before and/or after each test run. This provides an extra layer of protection *within the test environment*.
        *   **Transaction Management:** Wrap test cases in database transactions. This ensures that any changes made during the test are rolled back at the end, even if the test fails. Most testing frameworks provide this functionality *within the test environment*.
        *   **Least Privilege:** Database user accounts used for testing should have the minimum necessary privileges *on the test database*. They should *never* have access to the production database.

## Threat: [Masking of Authorization Vulnerabilities](./threats/masking_of_authorization_vulnerabilities.md)

*   **Description:** An attacker exploits an authorization vulnerability in the application that was not detected during testing. This is because the `factory_bot` factories used in the tests created objects with overly permissive attributes or roles (e.g., always creating an "admin" user). The tests passed because the factory-generated data bypassed the authorization checks, but real users with limited privileges would be able to exploit the same vulnerability.
    *   **Impact:**
        *   Unauthorized access to sensitive data or functionality.
        *   Elevation of privilege.
        *   Data breaches.
    *   **Affected Component:** Factory definitions, specifically the default attributes and associations defined within the `factory` block. Also, the way these factories are *used* within the tests themselves.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Multiple Factories/Traits:** Create multiple factories or traits to represent different user roles and permission levels (e.g., `user`, `admin_user`, `guest_user`).
        *   **Explicit Attribute Setting:** Within tests, explicitly set the attributes and roles of the objects being created, rather than relying solely on factory defaults. This forces developers to think about the required permissions for each test case.
        *   **Negative Testing:** Include tests that specifically check for *unauthorized* access. Create a user with limited privileges and verify that they *cannot* access protected resources or perform restricted actions.
        *   **Test-Driven Development (TDD):** Write tests *before* implementing the authorization logic. This helps ensure that the tests cover all relevant scenarios and that the authorization logic is correctly implemented.

