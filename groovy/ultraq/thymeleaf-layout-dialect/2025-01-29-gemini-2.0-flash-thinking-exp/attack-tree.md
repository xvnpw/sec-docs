# Attack Tree Analysis for ultraq/thymeleaf-layout-dialect

Objective: Achieve Remote Code Execution (RCE) on the server or gain unauthorized access to sensitive data by exploiting vulnerabilities in the application's use of Thymeleaf Layout Dialect.

## Attack Tree Visualization

```
Attack Goal: Compromise Application Using Thymeleaf Layout Dialect
├─── [HIGH-RISK PATH] 1. Exploit Server-Side Template Injection (SSTI) via Layout Dialect
│   ├─── [HIGH-RISK PATH] 1.1. Inject Malicious Thymeleaf Expressions via `layout:decorate` attribute
│   │   └─── [CRITICAL NODE] 1.1.1. Application dynamically constructs `layout:decorate` path from user input
│   │       └─── [CRITICAL NODE] 1.1.1.1. User input is not properly sanitized/validated before constructing path
│   │           └─── [CRITICAL NODE] [Success: SSTI leading to RCE or Data Exfiltration]
│   ├─── [HIGH-RISK PATH] 1.2. Inject Malicious Thymeleaf Expressions via `layout:include` or `layout:replace` attributes
│   │   └─── [CRITICAL NODE] 1.2.1. Application dynamically constructs `layout:include`/`layout:replace` path from user input
│   │       └─── [CRITICAL NODE] 1.2.1.1. User input is not properly sanitized/validated before constructing path
│   │           └─── [CRITICAL NODE] [Success: SSTI leading to RCE or Data Exfiltration]
│   └─── [HIGH-RISK PATH] 1.4. Exploit vulnerabilities in custom Layout Dialect processors (if implemented)
│       └─── 1.4.1. Application developers create custom processors that introduce SSTI vulnerabilities
│           └─── 1.4.1.1. Custom processors improperly handle user input or template expressions
│               └─── [CRITICAL NODE] [Success: SSTI leading to RCE or Data Exfiltration]
├─── [HIGH-RISK PATH] 2. Exploit Path Traversal via Fragment Inclusion/Decoration
│   ├─── [HIGH-RISK PATH] 2.1. Path Traversal via `layout:decorate` attribute
│   │   └─── [CRITICAL NODE] 2.1.1. Application allows user-controlled path segments in `layout:decorate`
│   │       └─── [CRITICAL NODE] 2.1.1.1. User can manipulate path to include files outside intended template directory
│   │           └─── [HIGH-RISK PATH] 2.1.1.1.2. Include malicious templates from attacker-controlled locations (leading to SSTI/RCE)
│   │               └─── [CRITICAL NODE] [Success: Include malicious templates from attacker-controlled locations (leading to SSTI/RCE)]
│   ├─── [HIGH-RISK PATH] 2.2. Path Traversal via `layout:include` or `layout:replace` attributes
│   │   └─── [CRITICAL NODE] 2.2.1. Application allows user-controlled path segments in `layout:include`/`layout:replace`
│   │       └─── [CRITICAL NODE] 2.2.1.1. User can manipulate path to include files outside intended template directory
│   │           └─── [HIGH-RISK PATH] 2.2.1.1.2. Include malicious templates from attacker-controlled locations (leading to SSTI/RCE)
│   │               └─── [CRITICAL NODE] [Success: Include malicious templates from attacker-controlled locations (leading to SSTI/RCE)]
```

## Attack Tree Path: [Exploit Server-Side Template Injection (SSTI) via Layout Dialect](./attack_tree_paths/exploit_server-side_template_injection__ssti__via_layout_dialect.md)

*   **Attack Vector:** Server-Side Template Injection (SSTI) occurs when user-controlled input is embedded into template expressions and processed by the template engine without proper sanitization. This allows an attacker to inject malicious code that is executed on the server.
*   **Critical Nodes within this path:**
    *   **[CRITICAL NODE] 1.1.1. Application dynamically constructs `layout:decorate` path from user input:**
        *   **Breakdown:** The application takes user input and uses it to build the path for the `layout:decorate` attribute. This is a dangerous practice if the input is not validated.
        *   **Impact:** If successful, an attacker can control the template path, potentially injecting malicious Thymeleaf expressions.
        *   **Mitigation:** Avoid dynamic path construction from user input. If necessary, use whitelisting, secure mapping, and strict input validation.
    *   **[CRITICAL NODE] 1.1.1.1. User input is not properly sanitized/validated before constructing path:**
        *   **Breakdown:**  The application fails to sanitize or validate the user input before using it in the template path. This is the core vulnerability enabling SSTI.
        *   **Impact:** Allows attackers to inject arbitrary Thymeleaf expressions.
        *   **Mitigation:** Implement robust input validation and sanitization. Treat all user input as untrusted.
    *   **[CRITICAL NODE] [Success: SSTI leading to RCE or Data Exfiltration]:**
        *   **Breakdown:** Successful exploitation of SSTI allows the attacker to execute arbitrary code on the server (RCE) or extract sensitive data.
        *   **Impact:** Complete system compromise, data breach, service disruption.
        *   **Mitigation:** Prevent SSTI by addressing the critical nodes above. Implement security measures like CSP and WAFs as defense in depth.
    *   **[CRITICAL NODE] 1.2.1. Application dynamically constructs `layout:include`/`layout:replace` path from user input:** (Similar breakdown and mitigations as 1.1.1, but for `layout:include` and `layout:replace` attributes)
    *   **[CRITICAL NODE] 1.2.1.1. User input is not properly sanitized/validated before constructing path:** (Similar breakdown and mitigations as 1.1.1.1, but for `layout:include` and `layout:replace` attributes)
    *   **[CRITICAL NODE] [Success: SSTI leading to RCE or Data Exfiltration]:** (Similar breakdown and mitigations as 1.1.1.1, but for `layout:include` and `layout:replace` attributes)
    *   **[CRITICAL NODE] [Success: SSTI leading to RCE or Data Exfiltration] (within 1.4.1.1):**
        *   **Breakdown:** If custom Layout Dialect processors are created and they improperly handle user input or template expressions, they can introduce SSTI vulnerabilities.
        *   **Impact:** RCE or Data Exfiltration through custom processors.
        *   **Mitigation:** Secure coding practices for custom processors, thorough security reviews, and penetration testing of custom extensions.

## Attack Tree Path: [Exploit Path Traversal via Fragment Inclusion/Decoration](./attack_tree_paths/exploit_path_traversal_via_fragment_inclusiondecoration.md)

*   **Attack Vector:** Path Traversal occurs when an attacker can manipulate file paths used by the application to access files outside of the intended directory. In the context of Thymeleaf Layout Dialect, this can happen if user input influences the paths used in `layout:decorate`, `layout:include`, or `layout:replace` attributes.
*   **Critical Nodes within this path:**
    *   **[CRITICAL NODE] 2.1.1. Application allows user-controlled path segments in `layout:decorate`:**
        *   **Breakdown:** The application allows user input to control parts of the path used in the `layout:decorate` attribute.
        *   **Impact:** Path traversal, potentially leading to reading sensitive files or including malicious templates.
        *   **Mitigation:**  Strictly validate and sanitize user input used in template paths. Use whitelisting and secure path handling.
    *   **[CRITICAL NODE] 2.1.1.1. User can manipulate path to include files outside intended template directory:**
        *   **Breakdown:** Due to insufficient validation, an attacker can use path traversal sequences (e.g., `../`) to navigate outside the intended template directory.
        *   **Impact:** Access to sensitive files, potential for including malicious templates from unexpected locations.
        *   **Mitigation:** Implement robust path validation to prevent traversal. Use secure path handling APIs.
    *   **[HIGH-RISK PATH] 2.1.1.1.2. Include malicious templates from attacker-controlled locations (leading to SSTI/RCE):**
        *   **Breakdown:** By exploiting path traversal, an attacker can include templates from locations they control (e.g., a public web server). These malicious templates can contain SSTI payloads.
        *   **Impact:** RCE through included malicious templates.
        *   **Mitigation:** Prevent path traversal. If external template inclusion is necessary, implement strict validation of template sources and content.
    *   **[CRITICAL NODE] [Success: Include malicious templates from attacker-controlled locations (leading to SSTI/RCE)]:**
        *   **Breakdown:** Successful path traversal and malicious template inclusion leads to SSTI and RCE.
        *   **Impact:** Complete system compromise, data breach, service disruption.
        *   **Mitigation:** Prevent path traversal and malicious template inclusion by addressing the critical nodes above.
    *   **[CRITICAL NODE] 2.2.1. Application allows user-controlled path segments in `layout:include`/`layout:replace`:** (Similar breakdown and mitigations as 2.1.1, but for `layout:include` and `layout:replace` attributes)
    *   **[CRITICAL NODE] 2.2.1.1. User can manipulate path to include files outside intended template directory:** (Similar breakdown and mitigations as 2.1.1.1, but for `layout:include` and `layout:replace` attributes)
    *   **[HIGH-RISK PATH] 2.2.1.1.2. Include malicious templates from attacker-controlled locations (leading to SSTI/RCE):** (Similar breakdown and mitigations as 2.1.1.1.2, but for `layout:include` and `layout:replace` attributes)
    *   **[CRITICAL NODE] [Success: Include malicious templates from attacker-controlled locations (leading to SSTI/RCE)]:** (Similar breakdown and mitigations as 2.1.1.1.2, but for `layout:include` and `layout:replace` attributes)

