## Threat Model: Hapi.js Application Compromise - High-Risk Paths and Critical Nodes

**Objective:** Compromise Hapi.js Application

**Sub-Tree of High-Risk Paths and Critical Nodes:**

```
└── Compromise Hapi.js Application
    ├── *** Exploit Routing Vulnerabilities (High-Risk Path) ***
    │   ├── Route Hijacking/Bypass
    │   │   └── Exploit Ambiguous Route Definitions
    │   │   └── Exploit Path Traversal in Route Parameters
    ├── *** Exploit Request Handling Weaknesses (High-Risk Path) ***
    │   ├── *** Payload Injection (Critical Node, High-Risk Path) ***
    │   │   ├── Exploit Server-Side Template Injection (SSTI) in rendered views (if used with templating engines).
    │   │   └── Inject malicious code through request parameters or headers that are not properly sanitized.
    ├── *** Exploit Authentication/Authorization Flaws (Critical Node, High-Risk Path) ***
    │   ├── Bypass Authentication Handlers
    │   ├── Exploit Authorization Logic
    │   ├── Session Hijacking/Fixation
    ├── *** Exploit Plugin Vulnerabilities (Critical Node, High-Risk Path) ***
    │   ├── Target Known Vulnerabilities in Hapi Plugins
    │   ├── Exploit Unmaintained or Custom Plugins
```

**Detailed Breakdown of Attack Vectors for High-Risk Paths and Critical Nodes:**

**1. Exploit Routing Vulnerabilities (High-Risk Path):**

*   **Route Hijacking/Bypass:** Hapi's routing mechanism relies on matching incoming requests to defined routes.
    *   **Exploit Ambiguous Route Definitions:** If routes are defined in a way that their patterns overlap, an attacker might be able to trigger an unintended route handler by crafting a specific request. This can lead to accessing functionalities or data that should be protected.
    *   **Exploit Path Traversal in Route Parameters:** If route parameters are not properly sanitized before being used to access resources (e.g., files), an attacker might use ".." sequences to navigate the file system and access sensitive files.

**2. Exploit Request Handling Weaknesses (High-Risk Path):**

*   **Payload Injection (Critical Node):**
    *   **Exploit Server-Side Template Injection (SSTI):** If the application uses a templating engine (e.g., Handlebars, Pug) with Hapi's `vision` plugin and user-controlled data is directly embedded into templates without proper sanitization, an attacker can inject malicious code that will be executed on the server.
    *   **Inject Malicious Code through Request Parameters or Headers:** If the application processes user input from request parameters or headers without proper sanitization, an attacker can inject malicious code (e.g., JavaScript for XSS, shell commands for command injection) that can be executed in the context of the application or the user's browser.

**3. Exploit Authentication/Authorization Flaws (Critical Node, High-Risk Path):**

*   **Bypass Authentication Handlers:** Hapi relies on plugins like `hapi-auth-jwt2` or `bell` for authentication. Vulnerabilities in these plugins or in custom authentication strategies can allow attackers to bypass authentication mechanisms. This could involve:
    *   Exploiting JWT vulnerabilities: Weak signing algorithms, insecure key management, or lack of proper token verification.
    *   Bypassing OAuth flows: Manipulating redirect URIs or exploiting flaws in the OAuth implementation.
*   **Exploit Authorization Logic:** Even with proper authentication, flaws in the authorization logic can allow attackers to access resources they shouldn't. This could involve:
    *   Exploiting vulnerabilities in RBAC implementations: Manipulating user roles or permissions.
    *   Bypassing access control checks: Finding loopholes in the logic that determines access to specific routes or functionalities.
*   **Session Hijacking/Fixation:** If session management is not implemented securely (often handled by plugins like `hapi-auth-cookie`), attackers can try to steal existing session IDs or force users to use a known session ID, gaining unauthorized access.

**4. Exploit Plugin Vulnerabilities (Critical Node, High-Risk Path):**

*   **Target Known Vulnerabilities in Hapi Plugins:** Many Hapi applications rely on a rich ecosystem of plugins. Attackers can target known vulnerabilities in popular plugins. Regularly checking for and updating plugin dependencies is crucial.
*   **Exploit Unmaintained or Custom Plugins:** Less common or custom-developed plugins might have undiscovered vulnerabilities due to lack of scrutiny or security best practices during development.