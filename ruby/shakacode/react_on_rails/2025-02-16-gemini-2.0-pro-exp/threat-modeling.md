# Threat Model Analysis for shakacode/react_on_rails

## Threat: [SSR Input Manipulation](./threats/ssr_input_manipulation.md)

*   **Threat:** SSR Input Manipulation

    *   **Description:** An attacker crafts malicious input (e.g., URL parameters, request headers, manipulated initial props, or data from a compromised database) that is passed to `react_on_rails`'s server-side rendering process.  This input exploits vulnerabilities in how the gem handles data before passing it to React's `renderToString` or `renderToStaticMarkup`, leading to server-side XSS-like vulnerabilities or other unintended code execution *on the server*. The attacker aims to inject JavaScript or manipulate the HTML structure *before* it reaches the client.
    *   **Impact:**
        *   Exposure of sensitive data included in the server-rendered HTML.
        *   Execution of arbitrary JavaScript code in the context of the server-rendered page (potentially leading to further attacks, including server compromise).
        *   Defacement of the website.
        *   Redirection to malicious websites.
    *   **Affected Component:** `react_component` helper (Rails side), Server-Side Rendering engine (Node.js side, specifically interacting with `react-dom/server` *through* `react_on_rails`'s API), and the React component being rendered.  The vulnerability lies in how `react_on_rails` bridges Rails data to the Node.js SSR environment.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Input Validation (Rails):** Before passing *any* data to `react_component`, rigorously validate and sanitize it on the Rails side. Use strong typing, whitelisting, and regular expressions.  This is the *primary* defense, as it prevents malicious data from ever reaching the SSR process.
        *   **Contextual Encoding (Rails):** Use Rails' built-in HTML escaping helpers (e.g., `h`, `sanitize`) to properly encode data within the rendered HTML, even on the server-side. This mitigates the risk of injected HTML tags.
        *   **Input Validation (React):** Implement input validation *within* the React component itself, even if the data is already validated on the Rails side. This provides defense-in-depth.
        *   **Limit SSR Scope:** Only use SSR for data that absolutely requires it.  Prefer client-side rendering for highly dynamic or user-controlled content.
        *   **Avoid `dangerouslySetInnerHTML` (React):** Never use `dangerouslySetInnerHTML` with untrusted data in server-rendered components.

## Threat: [Client-Side Component Hijacking](./threats/client-side_component_hijacking.md)

*   **Threat:** Client-Side Component Hijacking

    *   **Description:** An attacker injects a malicious script that leverages `react_on_rails`'s client-side component registration mechanism (`ReactOnRails.register`). The attacker registers a malicious component with the *same name* as a legitimate component. When `react_on_rails` attempts to render the component, it executes the attacker's malicious code instead.
    *   **Impact:**
        *   Execution of arbitrary JavaScript code in the user's browser.
        *   Theft of user data (e.g., form inputs, cookies).
        *   Defacement of the website.
        *   Redirection to malicious websites.
    *   **Affected Component:** `ReactOnRails.register` (client-side), the global component registry maintained by `react_on_rails`. The vulnerability is in the lack of built-in protection against overriding existing component registrations.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Content Security Policy (CSP):** Implement a strict CSP to prevent the execution of inline scripts and limit the sources from which scripts can be loaded. This is the *most effective* mitigation, as it prevents the initial script injection.
        *   **Subresource Integrity (SRI):** Use SRI for all JavaScript files to ensure that the client only executes the exact code that was intended. This prevents attackers from modifying existing scripts.
        *   **Secure Build Process:** Ensure your build process is secure and dependencies are vetted to prevent supply-chain attacks that could inject malicious code.
        *   **Code Reviews:** Conduct thorough code reviews to identify and prevent potential vulnerabilities that could allow script injection.

## Threat: [SSR Data Exposure](./threats/ssr_data_exposure.md)

*   **Threat:** SSR Data Exposure

    *   **Description:** Sensitive data is accidentally included in the props passed to a server-rendered component *via* the `react_component` helper.  `react_on_rails` then serializes these props and includes them in the initial HTML, exposing the data in the page source.
    *   **Impact:**
        *   Exposure of sensitive user data.
        *   Exposure of internal application secrets.
        *   Potential for further attacks based on the leaked information.
        *   Compliance violations.
    *   **Affected Component:** `react_component` helper (Rails side), the mechanism by which `react_on_rails` passes props to the server-rendered React component.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Careful Prop Selection:** Be extremely selective about what data is included in the props passed to `react_component`. Only include the *absolute minimum* necessary for the initial render.
        *   **Data Transformation (Rails):** Transform data on the Rails side *before* passing it to `react_component`. Create a separate "view model" or DTO that contains only non-sensitive data. This is the *most important* mitigation.
        *   **API for Sensitive Data:** For highly sensitive data, fetch it via an API call from the client-side *after* the initial render, rather than including it in the server-rendered HTML.
        *   **Code Reviews:** Conduct thorough code reviews to ensure that sensitive data is not accidentally included in server-rendered props.

## Threat: [Vulnerability in Node.js or SSR Libraries *used by react_on_rails*](./threats/vulnerability_in_node_js_or_ssr_libraries_used_by_react_on_rails.md)

* **Threat:** Vulnerability in Node.js or SSR Libraries *used by react_on_rails*

    * **Description:** A vulnerability exists in the Node.js runtime, `react-dom/server`, or another dependency *specifically used by react_on_rails for its SSR functionality*. An attacker exploits this vulnerability to gain control of the server or execute arbitrary code *through the SSR process initiated by react_on_rails*.
    * **Impact:**
        * Complete server compromise.
        * Execution of arbitrary code on the server.
        * Data breaches.
        * Denial of service.
    * **Affected Component:** Node.js runtime, `react-dom/server`, any dependency of `react_on_rails` *specifically involved in the SSR process*. The vulnerability is *not* in `react_on_rails` itself, but in a component it *uses*.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Keep Node.js Updated:** Regularly update your Node.js runtime to the latest stable version.
        * **Dependency Auditing:** Regularly audit your project's dependencies, *paying special attention to those involved in SSR*, for known vulnerabilities. Use `npm audit` or `yarn audit`.
        * **Vulnerability Scanning:** Use automated vulnerability scanning tools.
        * **Least Privilege:** Run the Node.js process (used by `react_on_rails` for SSR) with the least privileges necessary.
        * **Security Advisories:** Stay informed about security advisories related to Node.js, React, and `react_on_rails`.

