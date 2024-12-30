```
Title: High-Risk & Critical Threat Sub-Tree for Hanami Application

Objective: Gain Unauthorized Access or Control of the Hanami Application by Exploiting Hanami-Specific Weaknesses.

Goal: Compromise Hanami Application

Sub-Tree:

Compromise Hanami Application
├── OR Exploit Routing Vulnerabilities
│   └── AND Manipulate Route Parameters
│       └── Exploit Missing Parameter Validation [CRITICAL NODE] [HIGH-RISK PATH]
├── OR Exploit Action Vulnerabilities
│   ├── AND Exploit Mass Assignment Vulnerabilities [CRITICAL NODE]
│   └── AND Exploit Insecure Parameter Handling within Actions [HIGH-RISK PATH]
├── OR Exploit View/Template Rendering Vulnerabilities [HIGH-RISK PATH]
│   └── AND Exploit Server-Side Template Injection (SSTI) [CRITICAL NODE]
├── OR Exploit Dependency Vulnerabilities [HIGH-RISK PATH]
│   ├── AND Identify Vulnerable Hanami Dependencies [CRITICAL NODE]
│   └── AND Exploit Vulnerabilities in Hanami Itself [CRITICAL NODE]
├── OR Exploit Missing Authorization Checks in Specific Routes [CRITICAL NODE] [HIGH-RISK PATH]

Detailed Breakdown of Attack Vectors for High-Risk Paths and Critical Nodes:

High-Risk Path: Exploit Missing Parameter Validation
  * Attack Vector: Attackers manipulate route parameters by providing unexpected or malicious input due to the absence of proper validation.
  * Impact: Can lead to application errors, information disclosure (e.g., exposing debug information), or denial of service by causing crashes or resource exhaustion.
  * Mitigation: Implement comprehensive parameter validation for all route parameters, including type checking, format validation, and range checks.

High-Risk Path: Exploit Insecure Parameter Handling within Actions
  * Attack Vector: Attackers inject malicious payloads into parameters that are processed by Hanami actions without proper sanitization or validation.
  * Impact:
    * SQL Injection: If actions directly interact with the database (discouraged in Hanami), attackers can execute arbitrary SQL queries, leading to data breaches or manipulation.
    * Command Injection: If actions execute external commands based on user input, attackers can execute arbitrary commands on the server.
  * Mitigation:
    * Utilize Hanami's repository pattern and ORM features to prevent direct SQL manipulation. Employ parameterized queries.
    * Avoid executing external commands based on user input. If necessary, sanitize input rigorously and use safe execution methods.

High-Risk Path: Exploit View/Template Rendering Vulnerabilities
  * Attack Vector: Attackers inject malicious code into template variables that are rendered by Hanami's template engine.
  * Impact: Server-Side Template Injection (SSTI) allows attackers to execute arbitrary code on the server, potentially gaining full control of the application and the underlying system.
  * Mitigation: Avoid directly embedding user input into template code. Use safe rendering mechanisms and escape output appropriately. Review Hanami's template engine documentation for security best practices.

High-Risk Path: Exploit Dependency Vulnerabilities
  * Attack Vector: Attackers exploit known vulnerabilities in Hanami's dependencies (gems) by leveraging publicly available exploits or developing custom ones.
  * Impact: The impact varies depending on the specific vulnerability in the dependency, but it can range from information disclosure and denial of service to remote code execution.
  * Mitigation: Regularly update Hanami and its dependencies. Utilize dependency scanning tools to identify and address vulnerabilities.

High-Risk Path: Exploit Missing Authorization Checks in Specific Routes
  * Attack Vector: Attackers access routes that lack proper authorization checks, allowing them to perform actions or access data they are not permitted to.
  * Impact: Unauthorized access to sensitive functionality or data, potentially leading to data breaches, privilege escalation, or manipulation of critical application state.
  * Mitigation: Implement authorization checks for all routes requiring access control, ensuring that only authenticated and authorized users can access specific resources and functionalities.

Critical Node: Exploit Missing Parameter Validation
  * Attack Vector: As described in the High-Risk Path.
  * Impact: As described in the High-Risk Path.
  * Mitigation: As described in the High-Risk Path.

Critical Node: Exploit Mass Assignment Vulnerabilities
  * Attack Vector: Attackers manipulate request parameters to modify model attributes that are not intended to be directly accessible, potentially bypassing business logic or security constraints.
  * Impact: Modification of unintended model attributes, potentially leading to privilege escalation, data corruption, or bypassing security checks.
  * Mitigation: Utilize strong parameters in Hanami actions to explicitly define and permit only the intended attributes for mass assignment.

Critical Node: Exploit Server-Side Template Injection (SSTI)
  * Attack Vector: As described in the High-Risk Path.
  * Impact: As described in the High-Risk Path.
  * Mitigation: As described in the High-Risk Path.

Critical Node: Identify Vulnerable Hanami Dependencies
  * Attack Vector: Attackers identify outdated or vulnerable dependencies by analyzing the `Gemfile.lock` or by using automated vulnerability scanning tools.
  * Impact: This step is a prerequisite for exploiting vulnerabilities in dependencies, potentially leading to various attack vectors depending on the specific vulnerability.
  * Mitigation: Regularly audit and update dependencies. Use dependency scanning tools to proactively identify and address vulnerabilities.

Critical Node: Exploit Vulnerabilities in Hanami Itself
  * Attack Vector: Attackers exploit known vulnerabilities within the Hanami framework code itself.
  * Impact: Can lead to significant compromise, potentially allowing for remote code execution or complete application takeover.
  * Mitigation: Stay updated with Hanami security releases and apply patches promptly. Monitor Hanami security advisories and changelogs.

Critical Node: Exploit Missing Authorization Checks in Specific Routes
  * Attack Vector: As described in the High-Risk Path.
  * Impact: As described in the High-Risk Path.
  * Mitigation: As described in the High-Risk Path.
