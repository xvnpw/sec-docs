# Attack Tree Analysis for bpmn-io/bpmn-js

Objective: To execute arbitrary code within the user's browser or manipulate the application's state by exploiting vulnerabilities in the `bpmn-js` library.

## Attack Tree Visualization

```
Compromise Application Using bpmn-js **[CRITICAL NODE]**
* Exploit Vulnerabilities in BPMN XML Processing **[CRITICAL NODE]** **[HIGH-RISK PATH]**
    * Inject Malicious Script via BPMN XML **[CRITICAL NODE]** **[HIGH-RISK PATH]**
        * Embed JavaScript in BPMN elements (e.g., labels, documentation) **[HIGH-RISK PATH]**
        * Embed SVG with malicious script **[HIGH-RISK PATH]**
    * Trigger Cross-Site Scripting (XSS) via BPMN XML **[CRITICAL NODE]** **[HIGH-RISK PATH]**
* Exploit Vulnerabilities in Custom bpmn-js Extensions or Plugins **[CRITICAL NODE]**
* Social Engineering Attacks Leveraging bpmn-js Functionality
    * Phishing Attacks with Malicious BPMN Diagrams **[HIGH-RISK PATH]**
```


## Attack Tree Path: [Compromise Application Using bpmn-js](./attack_tree_paths/compromise_application_using_bpmn-js.md)

**[CRITICAL NODE]**
* This is the ultimate goal of the attacker and represents any successful exploitation of `bpmn-js` vulnerabilities leading to a compromise of the application's security or functionality.

## Attack Tree Path: [Exploit Vulnerabilities in BPMN XML Processing](./attack_tree_paths/exploit_vulnerabilities_in_bpmn_xml_processing.md)

**[CRITICAL NODE]** **[HIGH-RISK PATH]**
* This category represents attacks that leverage weaknesses in how `bpmn-js` parses and processes BPMN XML data.
    * **Attack Vectors:**
        * Injecting malicious scripts within BPMN XML elements.
        * Crafting BPMN XML that triggers XSS vulnerabilities during rendering.
        * Exploiting potential XXE vulnerabilities if server-side processing is involved.

## Attack Tree Path: [Inject Malicious Script via BPMN XML](./attack_tree_paths/inject_malicious_script_via_bpmn_xml.md)

**[CRITICAL NODE]** **[HIGH-RISK PATH]**
* Attackers aim to embed and execute malicious JavaScript code within the context of the user's browser by crafting specific BPMN XML.
    * **Attack Vectors:**
        * **Embed JavaScript in BPMN elements (e.g., labels, documentation) [HIGH-RISK PATH]:**
            *  Leveraging BPMN elements that allow text input (like labels, documentation fields) to inject JavaScript code.
            *  Exploiting event handlers or rendering logic that interprets and executes this injected script when the diagram is rendered or interacted with.
            *  **Example:** Using `<bpmn:textAnnotation><bpmn:text><script>alert('XSS')</script></bpmn:text></bpmn:textAnnotation>`.
        * **Embed SVG with malicious script [HIGH-RISK PATH]:**
            *  Embedding Scalable Vector Graphics (SVG) within BPMN diagrams, particularly within custom shapes or elements.
            *  Crafting the SVG to include `<script>` tags or event handlers (like `onload`) that execute malicious JavaScript when the SVG is rendered.
            *  **Example:** Using a custom BPMN shape that renders an SVG containing `<svg><script>...</script></svg>`.

## Attack Tree Path: [Embed JavaScript in BPMN elements (e.g., labels, documentation)](./attack_tree_paths/embed_javascript_in_bpmn_elements__e_g___labels__documentation_.md)

**[HIGH-RISK PATH]:**
            *  Leveraging BPMN elements that allow text input (like labels, documentation fields) to inject JavaScript code.
            *  Exploiting event handlers or rendering logic that interprets and executes this injected script when the diagram is rendered or interacted with.
            *  **Example:** Using `<bpmn:textAnnotation><bpmn:text><script>alert('XSS')</script></bpmn:text></bpmn:textAnnotation>`.

## Attack Tree Path: [Embed SVG with malicious script](./attack_tree_paths/embed_svg_with_malicious_script.md)

**[HIGH-RISK PATH]:**
            *  Embedding Scalable Vector Graphics (SVG) within BPMN diagrams, particularly within custom shapes or elements.
            *  Crafting the SVG to include `<script>` tags or event handlers (like `onload`) that execute malicious JavaScript when the SVG is rendered.
            *  **Example:** Using a custom BPMN shape that renders an SVG containing `<svg><script>...</script></svg>`.

## Attack Tree Path: [Trigger Cross-Site Scripting (XSS) via BPMN XML](./attack_tree_paths/trigger_cross-site_scripting__xss__via_bpmn_xml.md)

**[CRITICAL NODE]** **[HIGH-RISK PATH]**
* Attackers craft BPMN XML that, when rendered by `bpmn-js`, injects malicious HTML or JavaScript into the application's Document Object Model (DOM). This script then executes in the user's browser, within the application's origin.
    * **Attack Vectors:**
        *  Crafting BPMN XML where user-controlled data (e.g., task names, descriptions) is not properly sanitized or escaped before being rendered into the HTML.
        *  Leveraging specific BPMN elements or attributes that are vulnerable to injecting arbitrary HTML tags or JavaScript code.
        *  Exploiting inconsistencies between how the BPMN XML is parsed and how it's rendered into the DOM.
        *  **Example:** Using a task name like `<bpmn:task name="&lt;img src=x onerror=alert('XSS')&gt;" />`.

## Attack Tree Path: [Exploit Vulnerabilities in Custom bpmn-js Extensions or Plugins](./attack_tree_paths/exploit_vulnerabilities_in_custom_bpmn-js_extensions_or_plugins.md)

**[CRITICAL NODE]:**
* If the application utilizes custom extensions or plugins for `bpmn-js`, these can introduce security vulnerabilities if not developed with security in mind.
    * **Attack Vectors:**
        *  Lack of input validation in custom extension logic, allowing for injection attacks.
        *  Insecure handling of user data or API calls within the extension.
        *  Vulnerabilities in third-party libraries used by the custom extension.
        *  Exposing sensitive functionality or data through the custom extension's API.

## Attack Tree Path: [Social Engineering Attacks Leveraging bpmn-js Functionality](./attack_tree_paths/social_engineering_attacks_leveraging_bpmn-js_functionality.md)


* Attackers manipulate users into performing actions that compromise security, often by exploiting the visual nature of BPMN diagrams.
    * **Attack Vectors:**

## Attack Tree Path: [Phishing Attacks with Malicious BPMN Diagrams](./attack_tree_paths/phishing_attacks_with_malicious_bpmn_diagrams.md)

**[HIGH-RISK PATH]:**
            *  Embedding malicious links within BPMN diagram elements (e.g., hyperlinks in text annotations, URLs in documentation).
            *  Tricking users into clicking these links, leading them to phishing websites or triggering malicious downloads.
            *  Using deceptive text or visual cues within the diagram to encourage users to interact with malicious elements.
            *  **Example:** A BPMN diagram with a task labeled "Click here to update your password" linking to a fake login page.

