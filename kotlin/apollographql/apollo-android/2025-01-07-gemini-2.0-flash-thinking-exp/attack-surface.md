# Attack Surface Analysis for apollographql/apollo-android

## Attack Surface: [GraphQL Injection Vulnerabilities](./attack_surfaces/graphql_injection_vulnerabilities.md)

**Description:**  Occurs when user-controlled input is directly incorporated into GraphQL queries or mutations without proper sanitization or parameterization. This allows attackers to manipulate the query structure to access unauthorized data or perform unintended actions.

**How Apollo-Android Contributes:** If developers use string concatenation or manipulation to build GraphQL operations instead of leveraging Apollo's type-safe API and parameterized queries, they introduce this vulnerability.

**Example:** An application dynamically builds a query like `"{ users(where: { name: \"" + userInput + "\"}) { id, name } }"` where `userInput` comes directly from user input. An attacker could input `"}; mutation { deleteUser(id: \"admin\") }"` to execute a malicious mutation.

**Impact:** Unauthorized data access, data modification, privilege escalation, denial of service on the GraphQL server.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Utilize Apollo's Parameterized Queries:**  Always use variables for dynamic values in GraphQL operations. This ensures proper escaping and prevents injection.

## Attack Surface: [Insecure Local Data Caching](./attack_surfaces/insecure_local_data_caching.md)

**Description:**  Sensitive data fetched via GraphQL is stored locally by Apollo Client's caching mechanisms without adequate encryption or access controls.

**How Apollo-Android Contributes:** Apollo Client provides caching features that, if not configured securely, can lead to the exposure of cached data.

**Example:** User authentication tokens or personal information fetched through a GraphQL query are stored in the cache without encryption. If the device is compromised, this data can be easily accessed.

**Impact:** Exposure of sensitive user data, potential identity theft, unauthorized access to application features.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Encrypt the Apollo Cache:** Implement encryption for the local Apollo cache using Android's security features like `EncryptedSharedPreferences` or other secure storage mechanisms.
*   **Control Cache Expiration:**  Set appropriate cache expiration policies to minimize the window of opportunity for attackers to access stale but sensitive data.
*   **Avoid Caching Highly Sensitive Data:** For extremely sensitive information, consider bypassing the cache or using in-memory storage with appropriate safeguards.

## Attack Surface: [Insufficient TLS Configuration and Certificate Validation](./attack_surfaces/insufficient_tls_configuration_and_certificate_validation.md)

**Description:** The application fails to properly configure TLS or validate the server's SSL/TLS certificate when communicating with the GraphQL endpoint.

**How Apollo-Android Contributes:** Apollo Client handles network requests. If the default or custom `OkHttpClient` instance used by Apollo is not configured to enforce strong TLS settings and perform proper certificate validation, it introduces this risk.

**Example:** The application accepts any SSL certificate, making it vulnerable to man-in-the-middle (MITM) attacks where an attacker intercepts and potentially modifies communication.

**Impact:** Data breaches, interception of sensitive information (including authentication tokens), injection of malicious data.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Enforce TLS 1.2 or Higher:** Configure the `OkHttpClient` used by Apollo to only accept connections using TLS version 1.2 or higher.
*   **Implement Certificate Pinning:** Pin the expected server certificate or its public key to prevent MITM attacks using rogue certificates.

## Attack Surface: [Build Process and Configuration Issues](./attack_surfaces/build_process_and_configuration_issues.md)

**Description:**  Sensitive information, such as API keys or authentication tokens required for GraphQL communication, is stored insecurely within the application's build process or configuration files.

**How Apollo-Android Contributes:** The application needs to be configured with the GraphQL endpoint URL and potentially API keys or tokens to interact with the server using Apollo. If these are not handled securely, it creates a vulnerability.

**Example:** API keys are hardcoded directly in the application code or stored in plain text in configuration files that are included in the APK.

**Impact:**  Compromise of API keys, unauthorized access to the GraphQL API, potential data breaches.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Avoid Hardcoding Secrets:** Never hardcode API keys or authentication tokens directly in the application code.
*   **Use Secure Configuration Management:** Utilize secure methods for managing and storing API keys, such as environment variables or secure key management systems.

