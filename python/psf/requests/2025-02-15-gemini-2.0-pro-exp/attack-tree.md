# Attack Tree Analysis for psf/requests

Objective: To cause a significant negative impact on the application using `requests`, including but not limited to: data exfiltration, denial of service, or unintended resource consumption.

## Attack Tree Visualization

```
                                      Compromise Application Using Requests
                                                    |
        -------------------------------------------------------------------------
        |																											|
  1.  Data Exfiltration/Manipulation [CN]                               2. Denial of Service (DoS)
        |																											|
  -------																										 --------|
  |																																	|
1.1[CN]                                                                   2.1[HR]
SSRF[HR]                                                                  Timeout
                                                                          Abuse

```

## Attack Tree Path: [1. Data Exfiltration/Manipulation [CN]](./attack_tree_paths/1__data_exfiltrationmanipulation__cn_.md)

*   **Description:** This is the primary branch of the attack tree focused on gaining unauthorized access to data or modifying data through vulnerabilities in how the application uses the `requests` library. It's a critical node because success here often leads directly to the attacker's goal.
*   **Sub-Nodes:**
    *   **1.1 Server-Side Request Forgery (SSRF) via `requests` [CN][HR]**
        *   **Description:** An attacker crafts a malicious request that causes the application (using `requests`) to make unintended requests to internal or external resources. This is the *most significant* threat. `requests` doesn't inherently prevent SSRF; the application must validate URLs.
        *   **Example:** The application takes a user-provided URL and uses `requests.get(user_url)` without validation. The attacker provides `http://localhost:22`, `http://169.254.169.254/latest/meta-data/`, or `file:///etc/passwd`.
        *   **Mitigation:**
            *   **Strict URL Whitelisting:** Only allow requests to a predefined list of known-good domains and paths.
            *   **Input Validation:** Validate the user-provided URL *before* passing it to `requests`. Check:
                *   **Scheme:** Allow only `http` and `https`.
                *   **Hostname:** Avoid IPs if possible. Validate against a whitelist. *Never* allow loopback or link-local addresses.
                *   **Port:** Restrict to standard ports (80, 443).
                *   **Path:** Sanitize to prevent directory traversal.
            *   **Network Segmentation:** Restrict access to internal resources using firewalls and network policies.
            *   **Disable Redirects (if possible):** `allow_redirects=False`.
            *   **Custom Adapter:** Use a custom `requests.adapters.HTTPAdapter` for extra checks (e.g., hostname validation after DNS resolution).
        *   **Likelihood:** High (without proper validation) / Medium (with basic validation) / Low (with strict whitelisting)
        *   **Impact:** Very High (access to internal systems, sensitive data)
        *   **Effort:** Low (no validation) / Medium (basic validation) / High (strict whitelisting)
        *   **Skill Level:** Intermediate / Advanced
        *   **Detection Difficulty:** Medium / Hard

## Attack Tree Path: [2. Denial of Service (DoS)](./attack_tree_paths/2__denial_of_service__dos_.md)

*   **Description:** This branch focuses on making the application unavailable to legitimate users by exploiting vulnerabilities related to `requests`.
*   **Sub-Nodes:**
    *   **2.1 Timeout Abuse [HR]**
        *   **Description:** An attacker causes the application to hang by making requests to a server that delays its response. If the application doesn't set timeouts, it becomes unresponsive.
        *   **Mitigation:**
            *   **Set Timeouts:** *Always* use the `timeout` parameter (e.g., `requests.get(url, timeout=5)`). Consider separate connect and read timeouts: `timeout=(connect_timeout, read_timeout)`.
        *   **Likelihood:** High (if timeouts are not set) / Very Low (if timeouts are set)
        *   **Impact:** Medium to High (application unavailability)
        *   **Effort:** Very Low
        *   **Skill Level:** Novice
        *   **Detection Difficulty:** Easy

