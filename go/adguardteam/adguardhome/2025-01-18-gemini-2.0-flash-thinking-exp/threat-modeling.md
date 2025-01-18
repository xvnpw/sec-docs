# Threat Model Analysis for adguardteam/adguardhome

## Threat: [Weak or Default Administrative Credentials](./threats/weak_or_default_administrative_credentials.md)

**Description:** An attacker attempts to log in to the AdGuard Home administrative interface using default or easily guessable credentials. Upon successful authentication, the attacker gains full control over the AdGuard Home instance.

**Impact:** Complete compromise of AdGuard Home, allowing the attacker to modify filtering rules, access DNS query logs, disable protection, potentially pivot to other network resources, or use AdGuard Home for malicious purposes.

**Affected Component:** `web/handlers/auth.go` (Authentication module of the Admin Interface).

**Risk Severity:** Critical

**Mitigation Strategies:**
* Immediately change the default administrative username and password to strong, unique credentials during initial setup.
* Enforce strong password policies for administrative accounts.
* Consider implementing multi-factor authentication (if supported or through reverse proxy solutions).

## Threat: [Unsecured Publicly Accessible Admin Interface](./threats/unsecured_publicly_accessible_admin_interface.md)

**Description:** The AdGuard Home administrative interface is exposed to the public internet without proper access controls. An attacker can directly access the login page and attempt to brute-force credentials or exploit potential vulnerabilities in the interface.

**Impact:**  Unauthorized access to AdGuard Home, leading to the same impacts as weak credentials (rule modification, log access, service disruption, etc.).

**Affected Component:** `web/server.go` (HTTP server handling admin interface requests).

**Risk Severity:** Critical

**Mitigation Strategies:**
* Restrict access to the administrative interface to specific trusted IP addresses or networks using firewall rules.
* Place AdGuard Home behind a VPN or reverse proxy that provides authentication and access control.
* Disable remote access to the admin interface if not absolutely necessary.

## Threat: [API Key Exposure and Abuse](./threats/api_key_exposure_and_abuse.md)

**Description:** The AdGuard Home API key, used for programmatic access, is exposed through insecure storage, accidental disclosure, or a compromised application interacting with the API. An attacker with the API key can perform actions authorized by that key.

**Impact:** Depending on the permissions associated with the API key, an attacker could modify filtering rules, access statistics, manage clients, or perform other administrative tasks, leading to service disruption or data manipulation.

**Affected Component:** `service/api/handler.go` (API request handling and authentication).

**Risk Severity:** High

**Mitigation Strategies:**
* Store API keys securely, avoiding plain text storage in configuration files or code.
* Implement proper access control and authorization mechanisms for applications using the API.
* Regularly rotate API keys.
* Monitor API usage for suspicious activity.

## Threat: [Vulnerabilities in AdGuard Home Dependencies](./threats/vulnerabilities_in_adguard_home_dependencies.md)

**Description:** AdGuard Home relies on various third-party libraries and components. Vulnerabilities in these dependencies could be exploited to compromise AdGuard Home.

**Impact:** Depending on the vulnerability, this could lead to remote code execution, denial of service, or information disclosure.

**Affected Component:** Various, depending on the vulnerable dependency.

**Risk Severity:** Varies (can be High or Critical depending on the vulnerability).

**Mitigation Strategies:**
* Keep AdGuard Home updated to the latest version, which includes updates to its dependencies.
* Monitor security advisories for AdGuard Home and its dependencies.
* Implement a vulnerability management process to identify and address known vulnerabilities.

