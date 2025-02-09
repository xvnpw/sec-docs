# Attack Tree Analysis for dotnet/eshop

Objective: Gain Unauthorized Access to Sensitive Data AND/OR Disrupt Service

## Attack Tree Visualization

```
                                      +-------------------------------------------------+
                                      |  Attacker Goal: Gain Unauthorized Access to     |
                                      |  Sensitive Data AND/OR Disrupt Service          |
                                      +-------------------------------------------------+
                                                       |
          +----------------------------------------------------------------------------------------------------------------+
          |                                                                                                                |
+-------------------------+                                      +--------------------------------+
|  1. Compromise          |                                      |  2. Disrupt Service            |
|     Microservice(s)     |                                      |     Availability               |
+-------------------------+                                      +--------------------------------+
          |                                                                |
+---------------------+                                          +---------------------+
| 1.1 Exploit         |                                          | 2.1.1 Target        | [HR]
|     Vulnerable      |                                          |       Ordering      |
|     API Endpoint    |                                          |       Service       | [CN]
+---------------------+                                          +---------------------+
          |                                                                |
+---------------------+                                          +---------------------+
| 1.1.1 Bypass        |                                          | 2.1.1.1 Flood       | [HR]
|       AuthN/AuthZ   |                                          |       API           |
|       in API GW     |                                          |       Requests      |
+---------------------+                                          +---------------------+
          |
+---------------------+
| 1.1.1.1 Exploit     |
|       Ocelot        |
|       Config        |
+---------------------+
          | [HR]
+---------------------+
| 1.1.1.1.1 Find      |
|       Exposed      |
|       Sensitive    |
|       Routes       |
| L: Medium           |
| I: High             |
| E: Low              |
| S: Intermediate      |
| D: Medium           |
+---------------------+ [CN]
          | [HR]
+---------------------+
| L: Medium           |
| I: High             |
| E: Medium           |
| S: Advanced         |
| D: Hard             |
+---------------------+ [CN]
```

## Attack Tree Path: [High-Risk Path 1: Ocelot Misconfiguration Leading to Exposed Routes](./attack_tree_paths/high-risk_path_1_ocelot_misconfiguration_leading_to_exposed_routes.md)

*   **Overall Description:** This attack path exploits weaknesses in the configuration of the Ocelot API Gateway to gain direct access to backend microservices, bypassing authentication and authorization.

*   **Steps:**

    1.  **1.1.1.1 Exploit Ocelot Config [CN]:**
        *   **Description:** The attacker identifies and exploits a misconfiguration in the Ocelot API Gateway. This could involve finding weaknesses in routing rules, authentication settings, or other configuration parameters.
        *   **Likelihood:** Medium
        *   **Impact:** High
        *   **Effort:** Medium
        *   **Skill Level:** Advanced
        *   **Detection Difficulty:** Hard

    2.  **1.1.1.1.1 Find Exposed Sensitive Routes [CN]:**
        *   **Description:** Due to the Ocelot misconfiguration, the attacker is able to discover and access sensitive API endpoints that should be protected. This might involve using automated scanning tools or manual exploration.
        *   **Likelihood:** Medium
        *   **Impact:** High
        *   **Effort:** Low
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium

*   **Mitigation Strategies:**

    *   **Regularly audit and review Ocelot configuration:** Employ a "least privilege" approach, ensuring only necessary routes are exposed and strong authentication is enforced.
    *   **Use automated configuration scanning tools:** Detect misconfigurations proactively.
    *   **Implement robust input validation and sanitization:** Protect against injection attacks even if the gateway is bypassed.
    *   **Monitor API Gateway logs:** Look for suspicious activity, such as unauthorized access attempts.
    *   **Penetration testing:** Regularly test the API Gateway for vulnerabilities.

## Attack Tree Path: [High-Risk Path 2: DDoS Attack on Ordering Service](./attack_tree_paths/high-risk_path_2_ddos_attack_on_ordering_service.md)

*   **Overall Description:** This attack path focuses on disrupting the availability of the eShop application by overwhelming the Ordering microservice with a flood of requests.

*   **Steps:**

    1.  **2.1.1 Target Ordering Service [CN]:**
        *   **Description:** The attacker identifies the Ordering service as a critical component and targets it for a denial-of-service attack.
        *   **Likelihood:** High
        *   **Impact:** High
        *   **Effort:** Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium

    2.  **2.1.1.1 Flood API Requests [HR]:**
        *   **Description:** The attacker sends a massive number of requests to the Ordering service's API, exceeding its capacity and making it unavailable to legitimate users.
        *   **Likelihood:** High
        *   **Impact:** High
        *   **Effort:** Medium
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium

*   **Mitigation Strategies:**

    *   **Implement rate limiting and throttling:** Configure the API Gateway (Ocelot) and the Ordering service to limit the number of requests from a single source.
    *   **Use a Content Delivery Network (CDN):** Distribute content and absorb some of the attack traffic.
    *   **Implement circuit breakers:** Prevent cascading failures if the Ordering service becomes overloaded.
    *   **Use a Web Application Firewall (WAF):** Detect and block malicious traffic patterns.
    *   **Monitor network traffic:** Look for unusual spikes in requests to the Ordering service.
    *   **Have a DDoS response plan:** Define procedures for mitigating and recovering from a DDoS attack.

