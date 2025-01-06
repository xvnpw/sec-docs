## Deep Dive Analysis: OGNL Injection via HTTP Headers in Apache Struts

**To:** Development Team
**From:** Cybersecurity Expert
**Date:** October 26, 2023
**Subject:** In-depth Analysis of OGNL Injection via HTTP Headers Threat in Apache Struts Application

This document provides a comprehensive analysis of the "OGNL Injection via HTTP Headers" threat identified in our application's threat model, which utilizes the Apache Struts framework. We will delve into the mechanics of this attack, its potential impact, specific areas of concern within our application, and actionable mitigation strategies.

**1. Understanding the Threat: OGNL Injection via HTTP Headers**

This threat leverages the Object-Graph Navigation Language (OGNL) capabilities within the Apache Struts framework. OGNL is a powerful expression language used to access and manipulate data within Java objects. While beneficial for developers, it becomes a significant security risk when user-controlled input is directly evaluated as OGNL expressions.

Unlike the more commonly discussed OGNL injection via URL parameters, this variant focuses on injecting malicious OGNL code through HTTP headers. The core vulnerability lies in scenarios where:

* **Custom Interceptors:** Our application utilizes custom Struts interceptors that access and process HTTP header values. If these interceptors directly evaluate header values as OGNL expressions without proper sanitization, they become vulnerable.
* **Custom Type Converters:**  If custom type converters are used to transform header values into Java objects and these converters utilize OGNL for this process without adequate security measures, they can be exploited.
* **Direct Header Access:**  Code within our application (e.g., actions, services) directly retrieves and processes HTTP header values using OGNL.

**Key Difference from Parameter Injection:** While the underlying OGNL injection vulnerability is the same, the attack vector is different. Instead of manipulating URL parameters, attackers craft malicious HTTP requests with specially crafted header values. This can sometimes bypass basic input validation focused solely on URL parameters.

**2. How the Attack Works (Technical Breakdown)**

The attack unfolds in the following stages:

1. **Identifying Vulnerable Headers:** Attackers will probe the application to identify which HTTP headers are being processed and potentially evaluated as OGNL expressions. This might involve sending requests with various payloads in different headers and observing the application's behavior (e.g., error messages, server responses). Common targets could include custom headers, or even standard headers like `User-Agent`, `Referer`, or `X-Forwarded-For` if the application logic processes them using OGNL.

2. **Crafting Malicious OGNL Payloads:** Once a vulnerable header is identified, the attacker crafts a malicious OGNL expression. This expression can be designed to execute arbitrary Java code on the server. Examples of malicious payloads include:

   * **Command Execution:**  `%{ #rt=#context.get('com.opensymphony.xwork2.util.OgnlValueStack').getContext().get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter(), #rt.println("pwned"), #rt.flush(), #rt.close() }` (This example attempts to write "pwned" to the HTTP response).
   * **System Command Execution:** `%{ #a = new java.lang.ProcessBuilder(new java.lang.String[]{'/bin/bash','-c','whoami'}).start(), #b = #a.getInputStream(), #c = new java.io.InputStreamReader(#b), #d = new java.io.BufferedReader(#c), #e = #d.readLine(), #f = #context.get('com.opensymphony.xwork2.util.OgnlValueStack').getContext().get('com.opensymphony.xwork2.dispatcher.HttpServletResponse').getWriter(), #f.println(#e), #f.flush(), #f.close() }` (This example attempts to execute the `whoami` command).
   * **File System Access:**  Reading or writing files on the server.

3. **Sending the Malicious Request:** The attacker sends an HTTP request to the application with the malicious OGNL payload embedded within the targeted header.

4. **OGNL Evaluation and Code Execution:** If the application's code processes the vulnerable header using OGNL without proper sanitization, the malicious expression will be evaluated by the Struts framework. This leads to the execution of the attacker's arbitrary Java code on the server.

**3. Potential Impact (Reiteration)**

As stated in the threat description, the impact of successful OGNL injection via HTTP headers is **full server compromise**. This means an attacker can:

* **Execute arbitrary code:** Gain complete control over the server's operating system.
* **Access sensitive data:** Read confidential files, database credentials, and other sensitive information.
* **Modify data:** Alter application data, deface the website, or inject malicious content.
* **Install malware:** Deploy backdoors or other malicious software for persistent access.
* **Launch further attacks:** Use the compromised server as a staging point to attack other internal systems.
* **Cause denial of service:** Disrupt the application's availability.

**4. Identifying Vulnerable Components in Our Application**

To effectively mitigate this threat, we need to identify the specific areas in our application that might be vulnerable. We should focus our investigation on:

* **Custom Interceptors:**
    * Review the code of all custom interceptors, paying close attention to how they handle HTTP header values.
    * Look for any instances where `Ognl.getValue()` or similar OGNL evaluation methods are used directly on header values.
    * Identify if header values are being passed directly into OGNL expressions without sanitization.
* **Custom Type Converters:**
    * Examine custom type converters used for transforming HTTP header values.
    * Check if OGNL is used within these converters and how header values are processed.
* **Action and Service Layer Code:**
    * Search for code within our Struts actions or service layer that directly accesses HTTP headers and uses OGNL to process them.
    * Look for direct usage of `ServletActionContext.getRequest().getHeader()` followed by OGNL evaluation.
* **Configuration Files:**
    * While less likely, review Struts configuration files (`struts.xml`) for any unusual configurations related to header processing that might involve OGNL.

**Specific Questions to Ask During Code Review:**

* Does this code access HTTP headers?
* Is the retrieved header value directly used in an OGNL expression?
* Is there any input validation or sanitization applied to the header value before it's used in OGNL?
* Are there any logging statements that might reveal how header values are being processed?

**5. Mitigation Strategies**

Preventing OGNL injection via HTTP headers requires a multi-layered approach:

* **Avoid Using OGNL on User-Controlled Data (Strongest Recommendation):** The most effective solution is to **completely avoid using OGNL to process any data originating from HTTP headers**. Treat all header values as potentially malicious.
* **Input Validation and Sanitization:**
    * **Whitelist Known Good Values:** If possible, validate header values against a strict whitelist of acceptable characters and formats.
    * **Sanitize Input:**  Remove or escape characters that have special meaning in OGNL expressions. However, this can be complex and prone to bypasses. **Avoiding OGNL altogether is a more robust solution.**
* **Content Security Policy (CSP):** While not a direct mitigation for OGNL injection, a properly configured CSP can help limit the damage if an attack is successful by restricting the sources from which the browser can load resources.
* **Regular Security Audits and Penetration Testing:** Conduct regular security assessments, including penetration testing, to identify potential vulnerabilities. Specifically, test for OGNL injection in HTTP headers.
* **Keep Struts and Dependencies Up-to-Date:** Ensure that the Apache Struts framework and all its dependencies are updated to the latest versions. Security vulnerabilities are often discovered and patched in newer releases.
* **Principle of Least Privilege:** Ensure that the application server and the application itself are running with the minimum necessary privileges. This can limit the impact of a successful attack.
* **Web Application Firewall (WAF):** Implement a WAF that can inspect HTTP traffic and block requests with suspicious header values or known OGNL injection patterns. Configure the WAF to specifically look for malicious OGNL syntax in headers.
* **Secure Coding Practices:** Educate developers on secure coding practices, emphasizing the dangers of evaluating user-controlled input as code.

**6. Detection and Monitoring**

Even with preventative measures in place, it's crucial to have mechanisms for detecting potential attacks:

* **Intrusion Detection/Prevention Systems (IDS/IPS):** Configure IDS/IPS to monitor network traffic for suspicious patterns indicative of OGNL injection attempts in HTTP headers.
* **Web Application Firewall (WAF) Logging and Alerting:** Monitor WAF logs for blocked requests that contain potential OGNL injection payloads in headers. Set up alerts for such events.
* **Application Logging:** Implement comprehensive application logging that captures details of HTTP requests, including headers. Analyze these logs for unusual patterns or errors that might indicate an attack.
* **Security Information and Event Management (SIEM):** Integrate logs from various sources (WAF, IDS/IPS, application logs) into a SIEM system for centralized monitoring and analysis. Correlate events to detect potential attacks.
* **Error Monitoring:** Monitor application error logs for exceptions related to OGNL evaluation or unexpected behavior when processing headers.

**7. Immediate Actions and Recommendations**

Based on this analysis, the following immediate actions are recommended for the development team:

* **Prioritize Code Review:** Conduct a thorough code review focusing on the areas identified in section 4 (Custom Interceptors, Custom Type Converters, Action/Service Layer Code). Specifically look for OGNL usage on HTTP header values.
* **Disable or Refactor Vulnerable Code:** If any vulnerable code is identified, immediately disable it or refactor it to avoid using OGNL on header values.
* **Implement Input Validation:** If completely avoiding OGNL is not immediately feasible, implement robust input validation and sanitization for all HTTP header values being processed.
* **Update Struts Framework:** Ensure that the application is running on the latest stable and patched version of the Apache Struts framework.
* **Deploy WAF Rules:**  Configure the WAF with rules to detect and block common OGNL injection patterns in HTTP headers.

**8. Conclusion**

OGNL injection via HTTP headers is a critical threat that can lead to complete compromise of our application and the underlying server. Understanding the mechanics of this attack and proactively implementing mitigation strategies is paramount. By focusing on avoiding OGNL on user-controlled data, implementing robust input validation, and maintaining a strong security posture, we can significantly reduce the risk of this vulnerability being exploited. This analysis provides a starting point for our efforts, and continuous vigilance and proactive security measures are essential to protect our application.

Let's schedule a follow-up meeting to discuss these findings and plan the implementation of the recommended mitigation strategies.
