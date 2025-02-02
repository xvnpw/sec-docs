# Attack Tree Analysis for shopify/liquid

Objective: Compromise the application by exploiting vulnerabilities in Liquid template processing to achieve unauthorized access, data manipulation, or denial of service.

## Attack Tree Visualization

```
High-Risk Paths and Critical Nodes
├───[AND] Gain Unauthorized Access
│   └───[AND] Template Injection leading to Admin Access **[CRITICAL NODE]**
│       ├───[1.1.1] Inject Liquid code to manipulate control flow
│       │   └───[1.1.1.a] Exploit insecure use of `if`, `for`, `case` tags
│       └───[1.1.2] Inject Liquid code to access sensitive variables **[CRITICAL NODE]**
│           └───[1.1.2.a] Exploit insecure variable handling to access admin context
├───[OR] Server-Side Request Forgery (SSRF) via Liquid **[CRITICAL NODE]** **[HIGH-RISK PATH]** (Less likely in core Liquid, but possible with custom extensions)
│   └───[1.3.1] Abuse Liquid features to make external requests
│       └───[1.3.1.a] Exploit custom Liquid filters or tags that perform external requests without proper validation
├───[AND] Data Manipulation
│   ├───[OR] Content Injection/Defacement **[CRITICAL NODE]** **[HIGH-RISK PATH]**
│   │   └───[2.1.1] Template Injection leading to Content Modification
│   │       └───[2.1.1.a] Inject malicious HTML/JavaScript via Liquid template injection **[HIGH-RISK PATH]**
│   ├───[OR] Data Exfiltration **[CRITICAL NODE]** **[HIGH-RISK PATH]**
│   │   └───[2.2.1] Template Injection leading to Data Extraction
│   │       └───[2.2.1.a] Inject Liquid code to access and exfiltrate sensitive data variables **[HIGH-RISK PATH]**
```

## Attack Tree Path: [1. Template Injection leading to Admin Access [CRITICAL NODE]](./attack_tree_paths/1__template_injection_leading_to_admin_access__critical_node_.md)

**Attack Vector:** Injecting malicious Liquid code to bypass authentication or authorization checks, or to gain administrative privileges.
*   **Attack Step**:
    *   **1.1.1.a Exploit insecure use of `if`, `for`, `case` tags:**
        *   Likelihood: Low
        *   Impact: High (Admin Access)
        *   Effort: Medium
        *   Skill Level: Intermediate
        *   Detection Difficulty: Medium
        *   **Detailed Explanation:** If the application mistakenly uses Liquid template logic for critical authorization decisions (which is a poor practice), an attacker can inject Liquid code to manipulate conditional statements (`if`, `case`) or loops (`for`) to bypass these checks. For example, they might try to alter variables used in authorization logic or inject code that always evaluates to true in authorization conditions. This is high-risk because successful exploitation grants immediate administrative access, but likelihood is lower as proper application design should avoid this pattern.

    *   **1.1.2.a Exploit insecure variable handling to access admin context:**
        *   Likelihood: Medium
        *   Impact: High (Admin Context Exposure)
        *   Effort: Medium
        *   Skill Level: Intermediate
        *   Detection Difficulty: Medium
        *   **Detailed Explanation:** If sensitive variables related to admin status or permissions are inadvertently exposed to the Liquid template context (e.g., through global variables or improper context scoping), an attacker can inject Liquid code to access and display these variables. This information disclosure can then be used to further exploit the application, potentially leading to credential theft or direct admin access if the exposed variables directly control access. The risk is high because it can lead to full compromise, and the likelihood is medium as accidental exposure of sensitive context variables is a common mistake.

## Attack Tree Path: [2. Server-Side Request Forgery (SSRF) via Liquid [CRITICAL NODE] [HIGH-RISK PATH]](./attack_tree_paths/2__server-side_request_forgery__ssrf__via_liquid__critical_node___high-risk_path_.md)

**Attack Vector:** Abusing custom Liquid extensions to make unauthorized requests to internal or external resources.
*   **Attack Step**:
    *   **1.3.1.a Exploit custom Liquid filters or tags that perform external requests without proper validation:**
        *   Likelihood: Low
        *   Impact: High (SSRF, Internal Network Access)
        *   Effort: Medium
        *   Skill Level: Intermediate
        *   Detection Difficulty: Medium
        *   **Detailed Explanation:** If the application extends Liquid with custom filters or tags that perform HTTP requests (e.g., to fetch data from APIs, images, or other resources), and these extensions lack proper input validation, an attacker can manipulate the input to these filters/tags to control the destination of the requests. This allows them to perform SSRF attacks, potentially accessing internal network resources, reading sensitive files, or interacting with internal services that are not meant to be publicly accessible. The impact is high due to the potential for internal network compromise, but the likelihood is lower as it depends on the presence and insecurity of custom Liquid extensions.

## Attack Tree Path: [3. Content Injection/Defacement [CRITICAL NODE] [HIGH-RISK PATH]](./attack_tree_paths/3__content_injectiondefacement__critical_node___high-risk_path_.md)

**Attack Vector:** Injecting malicious HTML or JavaScript code into the application's content through template injection.
*   **Attack Step**:
    *   **2.1.1.a Inject malicious HTML/JavaScript via Liquid template injection [HIGH-RISK PATH]:**
        *   Likelihood: High
        *   Impact: Medium (Defacement, XSS)
        *   Effort: Low
        *   Skill Level: Beginner
        *   Detection Difficulty: Easy
        *   **Detailed Explanation:** This is the classic and most common template injection vulnerability. If user-controlled input is directly embedded into Liquid templates without proper sanitization or output encoding, an attacker can inject arbitrary HTML and JavaScript code. This leads to Cross-Site Scripting (XSS) attacks, allowing them to deface the website, steal user session cookies, redirect users to malicious sites, or perform other client-side attacks. The likelihood is high because it's a frequent mistake in web development, and the impact is medium as XSS can have significant consequences for users and the application's reputation.

## Attack Tree Path: [4. Data Exfiltration [CRITICAL NODE] [HIGH-RISK PATH]](./attack_tree_paths/4__data_exfiltration__critical_node___high-risk_path_.md)

**Attack Vector:** Injecting Liquid code to access and extract sensitive data from the application's context.
*   **Attack Step**:
    *   **2.2.1.a Inject Liquid code to access and exfiltrate sensitive data variables [HIGH-RISK PATH]:**
        *   Likelihood: Medium
        *   Impact: High (Sensitive Data Breach)
        *   Effort: Medium
        *   Skill Level: Intermediate
        *   Detection Difficulty: Medium
        *   **Detailed Explanation:** If template injection is possible, an attacker can inject Liquid code to access variables within the Liquid context that contain sensitive data (e.g., user data, API keys, internal configuration). They can then use Liquid's output mechanisms to extract this data. This could involve displaying the data directly, embedding it in URLs, or using JavaScript (if XSS is also achieved) to send the data to an attacker-controlled server. The impact is high due to the potential for sensitive data breaches, and the likelihood is medium as it depends on the presence of template injection vulnerabilities and the exposure of sensitive data in the Liquid context.

