# Attack Tree Analysis for apache/struts

Objective: [Attacker's Goal: RCE via Struts Vulnerability]***

## Attack Tree Visualization

[Attacker's Goal: RCE via Struts Vulnerability]***
    |
    -------------------------------------------------------------------------
    |                                                                       |
[Exploit Parameter Injection Vulnerabilities]***        [Exploit Class Loading/OGNL Injection Vulnerabilities]***
    |
    |                                   -----------------------------------------------------------------
    |                                   |                                                               |
[Force OGNL Evaluation via Parameter]***  [Exploit ClassLoader Manipulation]***        [OGNL Expression Injection]***
    |                                   |                                                               |
    |                                   |                                       ---------------------------------
    |                                   |                                       |                               |
[CVE-2017-5638 (Content-Type)]***   [Load Malicious Class]***        [Vulnerable Result Types]***
    |                                                                       |
[Craft Malicious Content-Type]***                                           [e.g., Freemarker]***
    |
[Send Crafted HTTP Request]***

## Attack Tree Path: [High-Risk Path 1: Parameter Injection (CVE-2017-5638)](./attack_tree_paths/high-risk_path_1_parameter_injection__cve-2017-5638_.md)

1.  **[Exploit Parameter Injection Vulnerabilities]***:
    *   **Description:** Attackers leverage flaws in how Struts handles user-supplied parameters to inject malicious code or control application behavior. This is a broad category encompassing various techniques.
    *   **Mechanism:** Struts uses parameters from HTTP requests (GET, POST, headers) to populate action properties. Vulnerabilities can arise when these parameters are not properly validated or sanitized.
    *   **Example:** Injecting OGNL expressions into parameters that are unexpectedly evaluated.

2.  **[Force OGNL Evaluation via Parameter]***:
    *   **Description:** The attacker crafts input that forces Struts to interpret a parameter value as an OGNL (Object-Graph Navigation Language) expression.
    *   **Mechanism:** OGNL is a powerful expression language used by Struts. If an attacker can control the content of an OGNL expression, they can often execute arbitrary code.
    *   **Example:** Using specially crafted characters or sequences to trigger OGNL evaluation where it's not intended.

3.  **[CVE-2017-5638 (Content-Type)]***:
    *   **Description:** A specific, highly critical vulnerability where a malicious `Content-Type` header in an HTTP request leads to OGNL expression evaluation.
    *   **Mechanism:** The Jakarta Multipart parser in Struts improperly handles exceptions when processing the `Content-Type` header, leading to the evaluation of attacker-controlled OGNL expressions.
    *   **Example:** Sending a request with a `Content-Type` header like: `Content-Type: ${(#_='multipart/form-data')...}` (simplified example).

4.  **[Craft Malicious Content-Type]***:
    *   **Description:** The attacker constructs a specially formatted `Content-Type` header containing the OGNL payload.
    *   **Mechanism:** The payload is designed to exploit the vulnerability in the Jakarta Multipart parser.
    *   **Example:** A complex OGNL expression that executes system commands.

5.  **[Send Crafted HTTP Request]***:
    *   **Description:** The attacker sends the HTTP request with the malicious `Content-Type` header to the vulnerable Struts application.
    *   **Mechanism:** This triggers the vulnerability and executes the OGNL payload.
    *   **Example:** Using tools like `curl`, `wget`, or a custom script to send the request.

## Attack Tree Path: [High-Risk Path 2: OGNL Injection via Result Types](./attack_tree_paths/high-risk_path_2_ognl_injection_via_result_types.md)

1.  **[Exploit Class Loading/OGNL Injection Vulnerabilities]***:
    *   **Description:** This is a broader category that includes vulnerabilities related to how Struts loads classes and handles OGNL expressions, specifically within result processing.
    *   **Mechanism:** Struts uses "results" to determine how to render the response to a request (e.g., displaying a JSP page, rendering a Freemarker template). Vulnerabilities can occur if these results are not properly secured.

2.  **[OGNL Expression Injection]***:
    *   **Description:** The attacker injects malicious OGNL expressions into parts of the application that are processed by Struts' result rendering mechanism.
    *   **Mechanism:** Similar to parameter injection, but the injection point is within the result configuration or data passed to the result.

3.  **[Vulnerable Result Types]***:
    *   **Description:** Certain Struts result types, particularly those that use template engines (like Freemarker or Velocity), are more susceptible to OGNL injection if not configured securely.
    *   **Mechanism:** These result types often evaluate expressions within templates, and if user-supplied data is included in these expressions without proper escaping, it can lead to OGNL injection.

4.  **[e.g., Freemarker]***:
    *   **Description:** Freemarker is a popular template engine used with Struts. It's a common target for OGNL injection.
    *   **Mechanism:** If a Freemarker template includes user-supplied data directly in an expression (e.g., `${user.name}` where `user.name` is attacker-controlled), it can be exploited.
    *   **Example:**  If a result configuration uses a Freemarker template and passes unsanitized user input to it, the attacker can inject OGNL expressions into that input.

## Attack Tree Path: [High-Risk Path 3: Class Loader Manipulation](./attack_tree_paths/high-risk_path_3_class_loader_manipulation.md)

1.  **[Exploit Class Loading/OGNL Injection Vulnerabilities]***:
    *   **Description:**  This broad category encompasses vulnerabilities related to how Struts loads classes, potentially allowing attackers to load malicious classes.

2.  **[Exploit ClassLoader Manipulation]***:
    *   **Description:** The attacker manipulates the Java class loading mechanism used by Struts to load a class of their choosing.
    *   **Mechanism:**  Java's class loading is a complex process.  Vulnerabilities can allow attackers to influence which class loader is used, where classes are loaded from, or even to inject bytecode directly.
    *   **Example:**  Exploiting a vulnerability that allows specifying a class name via a parameter, then providing the name of a malicious class.

3.  **[Load Malicious Class]***:
    *   **Description:** The attacker successfully loads a class they control into the Struts application's context.
    *   **Mechanism:**  This typically involves exploiting a class loading vulnerability to load a class from an attacker-controlled location (e.g., a remote URL or a specially crafted JAR file).
    *   **Example:**  The malicious class might contain code that executes system commands, opens a reverse shell, or exfiltrates data.

