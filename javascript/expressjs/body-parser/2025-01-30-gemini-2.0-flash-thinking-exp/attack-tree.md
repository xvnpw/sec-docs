# Attack Tree Analysis for expressjs/body-parser

Objective: Compromise Application using Body-Parser Vulnerabilities

## Attack Tree Visualization

└── Compromise Application using Body-Parser **[CRITICAL NODE: Attacker Goal]**
    ├── Exploit Parsing Vulnerabilities (OR) **[CRITICAL NODE: Vulnerability Category]**
    │   ├── Denial of Service (DoS) (OR) **[CRITICAL NODE: High Impact]**
    │   │   ├── **[HIGH-RISK PATH]** Resource Exhaustion via Large Payloads (AND)
    │   │   │   ├── **[HIGH-RISK PATH]** Send Extremely Large JSON Payload
    │   │   │   │   └── **[CRITICAL NODE: Misconfiguration]** No Input Size Limit configured for JSON Parser
    │   │   │   ├── **[HIGH-RISK PATH]** Send Extremely Large URL-encoded Payload
    │   │   │   │   └── **[CRITICAL NODE: Misconfiguration]** No Input Size Limit configured for URL-encoded Parser
    │   ├── **[HIGH-RISK PATH]** Prototype Pollution (AND) **[CRITICAL NODE: Vulnerability Type]**
    │   │   ├── **[HIGH-RISK PATH]** Send Malicious JSON/URL-encoded Payload (AND)
    │   │   │   ├── **[HIGH-RISK PATH]** Craft Payload with "__proto__", "constructor", or "prototype" properties
    │   │   │   │   └── **[CRITICAL NODE: Vulnerable Parsing Logic]** Body-parser's parsing logic improperly handles or fails to sanitize these properties
    │   │   ├── Exploit Prototype Pollution to Achieve (OR)
    │   │   │   ├── Remote Code Execution (RCE) (AND) **[CRITICAL NODE: Very High Impact]**
    │   │   │   ├── Logic Manipulation/Application State Change (AND) **[CRITICAL NODE: High Impact]**
    │   ├── Parameter Pollution (URL-encoded) (AND)
    │   │   ├── Exploit Parameter Pollution to Achieve (OR)
    │   │   │   ├── Bypass Authentication/Authorization (AND) **[CRITICAL NODE: High Impact]**

## Attack Tree Path: [Denial of Service (DoS) via Resource Exhaustion - Large Payloads](./attack_tree_paths/denial_of_service__dos__via_resource_exhaustion_-_large_payloads.md)

**Attack Vector:** Sending excessively large JSON or URL-encoded payloads to the application.
*   **Vulnerability Exploited:** Lack of input size limits configured in body-parser for JSON and URL-encoded parsers. This allows attackers to send requests that consume excessive server resources (CPU, memory, bandwidth).
*   **Critical Nodes Involved:**
    *   **Compromise Application using Body-Parser [CRITICAL NODE: Attacker Goal]:** This is the ultimate goal of the attacker.
    *   **Exploit Parsing Vulnerabilities [CRITICAL NODE: Vulnerability Category]:**  This attack falls under the category of exploiting parsing weaknesses in body-parser.
    *   **Denial of Service (DoS) [CRITICAL NODE: High Impact]:** The direct impact of this attack is to make the application unavailable.
    *   **Resource Exhaustion via Large Payloads [HIGH-RISK PATH]:** This is the specific method used to achieve DoS.
    *   **Send Extremely Large JSON Payload / Send Extremely Large URL-encoded Payload [HIGH-RISK PATH]:** These are the concrete actions the attacker takes.
    *   **No Input Size Limit configured for JSON Parser / No Input Size Limit configured for URL-encoded Parser [CRITICAL NODE: Misconfiguration]:** This is the root cause vulnerability – a configuration oversight.
*   **Potential Impact:** Application unavailability, server crash, service disruption for legitimate users.
*   **Mitigation Strategies:**
    *   **Configure Request Size Limits:** Use the `limit` option in `bodyParser.json()` and `bodyParser.urlencoded()` to restrict the maximum size of request bodies.
    *   **Web Application Firewall (WAF):** Deploy a WAF to filter out requests with excessively large bodies.
    *   **Rate Limiting:** Implement rate limiting to restrict the number of requests from a single IP address.

## Attack Tree Path: [Prototype Pollution](./attack_tree_paths/prototype_pollution.md)

**Attack Vector:** Sending malicious JSON or URL-encoded payloads containing properties like `__proto__`, `constructor`, or `prototype`.
*   **Vulnerability Exploited:** Body-parser's parsing logic might improperly handle or fail to sanitize these special properties, leading to modification of JavaScript object prototypes.
*   **Critical Nodes Involved:**
    *   **Compromise Application using Body-Parser [CRITICAL NODE: Attacker Goal]:** The ultimate goal.
    *   **Exploit Parsing Vulnerabilities [CRITICAL NODE: Vulnerability Category]:** Prototype pollution is a parsing vulnerability.
    *   **Prototype Pollution [HIGH-RISK PATH, CRITICAL NODE: Vulnerability Type]:** This is the specific vulnerability being exploited.
    *   **Send Malicious JSON/URL-encoded Payload [HIGH-RISK PATH]:** The attacker's action to inject the malicious payload.
    *   **Craft Payload with "__proto__", "constructor", or "prototype" properties [HIGH-RISK PATH]:**  The specific payload crafting technique.
    *   **Vulnerable Parsing Logic [CRITICAL NODE: Vulnerable Parsing Logic]:**  The underlying weakness in body-parser's handling of these properties.
    *   **Remote Code Execution (RCE) [CRITICAL NODE: Very High Impact]:** A potential severe outcome of prototype pollution.
    *   **Logic Manipulation/Application State Change [CRITICAL NODE: High Impact]:** Another significant outcome, leading to application malfunction.
*   **Potential Impact:**
    *   **Remote Code Execution (RCE):** If polluted prototypes are used in vulnerable code paths (e.g., insecure templating, dynamic code execution).
    *   **Logic Manipulation/Application State Change:**  Unexpected application behavior, data corruption, privilege escalation due to altered object behavior.
*   **Mitigation Strategies:**
    *   **Use `Object.create(null)`:** Create objects without a prototype chain when processing parsed data.
    *   **Input Sanitization and Validation:** Reject or escape `__proto__`, `constructor`, and `prototype` properties in input.
    *   **Content Security Policy (CSP):** Implement CSP to limit the impact of potential RCE.
    *   **Regularly Update Dependencies:** Keep body-parser and dependencies updated.
    *   **Security Audits and Code Reviews:**  Focus on prototype pollution vulnerabilities.

## Attack Tree Path: [Parameter Pollution (URL-encoded) leading to Bypass Authentication/Authorization](./attack_tree_paths/parameter_pollution__url-encoded__leading_to_bypass_authenticationauthorization.md)

**Attack Vector:** Sending multiple parameters with the same name in a URL-encoded body to manipulate application logic, specifically authentication or authorization checks.
*   **Vulnerability Exploited:** Application logic incorrectly assumes how body-parser handles duplicate parameters (e.g., trusting only the first or last value) and uses polluted parameters for security decisions.
*   **Critical Nodes Involved:**
    *   **Compromise Application using Body-Parser [CRITICAL NODE: Attacker Goal]:** The overall objective.
    *   **Exploit Parsing Vulnerabilities [CRITICAL NODE: Vulnerability Category]:** Parameter pollution arises from parsing behavior.
    *   **Parameter Pollution (URL-encoded):** The specific vulnerability type.
    *   **Exploit Parameter Pollution to Achieve Bypass Authentication/Authorization [HIGH-RISK PATH, CRITICAL NODE: High Impact]:**  A high-impact outcome of parameter pollution.
    *   **Bypass Authentication/Authorization [CRITICAL NODE: High Impact]:** The direct security impact.
*   **Potential Impact:** Unauthorized access to application resources, privilege escalation, data breaches.
*   **Mitigation Strategies:**
    *   **Understand Body-parser's Parameter Handling:** Document and test how body-parser handles duplicate parameters.
    *   **Explicit Parameter Handling in Application Logic:**  Do not rely on implicit behavior. Handle parameters explicitly, considering the possibility of multiple values.
    *   **Input Validation and Sanitization:** Validate and sanitize all input parameters.
    *   **Framework-Level Mitigation:** Utilize framework features for handling parameter pollution if available.

