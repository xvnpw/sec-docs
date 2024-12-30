## High-Risk Sub-Tree: Compromising Applications Using Shopify Liquid

**Goal:** Compromise application using Liquid by exploiting its weaknesses.

**High-Risk Sub-Tree:**

* **[CRITICAL] Compromise Application Using Liquid**
    * OR: **[CRITICAL] Achieve Code Execution**
        * **[HIGH-RISK PATH]** AND: **[CRITICAL] Server-Side Template Injection (SSTI)**
            * **[HIGH-RISK NODE]** Inject Malicious Liquid Code
                * **[HIGH-RISK NODE]** Via User-Controlled Input (e.g., form fields, URL parameters)
                    * Exploit Inadequate Input Sanitization/Escaping
            * Trigger Execution of Injected Code
    * OR: **[CRITICAL] Achieve Information Disclosure**
        * **[HIGH-RISK PATH]** AND: Access Sensitive Data via Template Logic Errors
            * **[HIGH-RISK NODE]** Exploit Conditional Logic Flaws
                * Manipulate Data to Bypass Access Controls in Templates
            * **[HIGH-RISK NODE]** Exploit Insecure Use of Liquid Objects/Variables
                * Access Objects or Variables Containing Sensitive Information Not Intended for Display

**Detailed Breakdown of Attack Vectors for High-Risk Paths and Critical Nodes:**

* **[CRITICAL] Compromise Application Using Liquid:** This is the ultimate goal of the attacker. It signifies a successful breach of the application's security, potentially leading to unauthorized access, data manipulation, or complete control.

* **[CRITICAL] Achieve Code Execution:** This critical node represents the attacker's ability to execute arbitrary code within the application's environment. This is a highly severe outcome, potentially allowing for complete system takeover, data exfiltration, or further malicious activities.

* **[HIGH-RISK PATH] Server-Side Template Injection (SSTI):** This path describes the attack where an attacker injects malicious Liquid code that is then processed and executed on the server. This is a high-risk path due to the potential for critical impact (code execution) and the possibility of exploiting common vulnerabilities.

* **[CRITICAL] Server-Side Template Injection (SSTI):** Achieving SSTI is a critical step as it directly leads to the ability to execute code on the server.

* **[HIGH-RISK NODE] Inject Malicious Liquid Code:** This node represents the core action of the SSTI attack. The attacker aims to insert malicious Liquid syntax into a template that will be processed by the server.

* **[HIGH-RISK NODE] Via User-Controlled Input (e.g., form fields, URL parameters):** This highlights a common and often easily exploitable injection point. If user-provided data is directly or indirectly used in rendering a Liquid template without proper sanitization, attackers can inject malicious code.

* **Exploit Inadequate Input Sanitization/Escaping:** This is the underlying vulnerability that enables the "Via User-Controlled Input" attack. If the application fails to properly sanitize or escape user input before using it in a Liquid template, the injected code will be interpreted and executed.

* **Trigger Execution of Injected Code:** Once malicious Liquid code is injected, this step represents the server processing the template containing the malicious code, leading to its execution.

* **[CRITICAL] Achieve Information Disclosure:** This critical node represents the attacker's ability to access sensitive information that they are not authorized to view. This can have significant consequences depending on the nature of the disclosed data.

* **[HIGH-RISK PATH] Access Sensitive Data via Template Logic Errors:** This path describes how attackers can exploit flaws in the logic of Liquid templates to gain access to sensitive information. This is a high-risk path because logic errors are common and can inadvertently expose sensitive data.

* **[HIGH-RISK NODE] Exploit Conditional Logic Flaws:** This node focuses on exploiting errors in the conditional statements within Liquid templates. Attackers might manipulate data or parameters to bypass intended access controls and reveal restricted information.

* **Manipulate Data to Bypass Access Controls in Templates:** This describes the specific technique used to exploit conditional logic flaws. Attackers craft input or manipulate data in a way that causes the template's conditional logic to evaluate incorrectly, granting them access to sensitive data.

* **[HIGH-RISK NODE] Exploit Insecure Use of Liquid Objects/Variables:** This node highlights the risk of directly accessing Liquid objects or variables that contain sensitive information without proper filtering or access control within the template.

* **Access Objects or Variables Containing Sensitive Information Not Intended for Display:** This describes the direct access of sensitive data within the template. If developers inadvertently expose sensitive data through Liquid objects or variables, attackers can easily retrieve it.