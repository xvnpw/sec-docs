# Attack Tree Analysis for erusev/parsedown

Objective: Compromise application via Parsedown

## Attack Tree Visualization

```
*   OR: Exploit Parsedown Vulnerabilities [CRITICAL]
    *   ***AND: Client-Side Exploitation (Leads to XSS)***
        *   OR: Inject Malicious HTML
            *   ***Inject Raw HTML Tags (e.g., <script>, <iframe>, <object>)***
            *   ***Inject HTML through Markdown Features***
                *   ***Exploit `javascript:` URLs in links***
                *   ***Exploit image tags with event handlers (e.g., `<img src="x" onerror="alert(1)">`)***
                *   ***Exploit iframe/object tags within allowed HTML***
        *   OR: Exploit Markdown Rendering Logic for XSS
            *   ***Bypass Sanitization with Clever Markdown***
```


## Attack Tree Path: [Client-Side Exploitation (Leads to XSS)](./attack_tree_paths/client-side_exploitation__leads_to_xss_.md)

*   Description: This path represents the most significant risk, where an attacker leverages Parsedown's functionality or vulnerabilities to inject malicious scripts that execute in the victim's browser. This can lead to account takeover, data theft, and other malicious activities.

## Attack Tree Path: [Exploit Parsedown Vulnerabilities](./attack_tree_paths/exploit_parsedown_vulnerabilities.md)

*   Description: This is the root of the high-risk subtree, indicating that the compromise originates from exploiting weaknesses within Parsedown itself. Successfully exploiting this node opens up various avenues for attack, primarily client-side exploitation.

## Attack Tree Path: [Inject Raw HTML Tags (e.g., <script>, <iframe>, <object>)](./attack_tree_paths/inject_raw_html_tags__e_g___script__iframe__object_.md)

*   Description: If Parsedown is configured to allow raw HTML input, attackers can directly embed malicious HTML tags like `<script>` to execute JavaScript, `<iframe>` to embed malicious content from other sites, or `<object>` for similar purposes.
*   Likelihood: Medium - Depends on Parsedown's configuration and the application's input handling.
*   Impact: High - Full client-side compromise.
*   Effort: Low - Requires basic knowledge of HTML.
*   Skill Level: Low.
*   Detection Difficulty: Medium - Depends on the effectiveness of output sanitization.

## Attack Tree Path: [Inject HTML through Markdown Features](./attack_tree_paths/inject_html_through_markdown_features.md)

*   Description: Even if raw HTML is restricted, attackers can exploit Markdown syntax to inject malicious HTML.

    *   Attack Vector: Exploit `javascript:` URLs in links
        *   Description:  Using Markdown link syntax like `[Click Me](javascript:maliciousCode())` can result in the generation of an `<a href="javascript:maliciousCode()">` tag, executing the JavaScript when the link is clicked.
        *   Likelihood: Medium - Common XSS technique.
        *   Impact: High - Full client-side compromise.
        *   Effort: Low.
        *   Skill Level: Low.
        *   Detection Difficulty: Medium.

    *   Attack Vector: Exploit image tags with event handlers (e.g., `<img src="x" onerror="alert(1)">`)
        *   Description: While not standard Markdown, if raw HTML attributes are allowed or if Parsedown mishandles certain input, attackers might inject image tags with event handlers like `onerror` or `onload` that execute JavaScript.
        *   Likelihood: Medium - Well-known XSS technique.
        *   Impact: High - Full client-side compromise.
        *   Effort: Low.
        *   Skill Level: Low.
        *   Detection Difficulty: Medium.

    *   Attack Vector: Exploit iframe/object tags within allowed HTML
        *   Description: If some HTML tags are allowed but not properly sanitized, attackers can use `<iframe>` or `<object>` tags to embed malicious content from external sources.
        *   Likelihood: Medium - If some HTML is allowed.
        *   Impact: High - Full client-side compromise, potential for embedding malicious content.
        *   Effort: Low.
        *   Skill Level: Low.
        *   Detection Difficulty: Medium.

## Attack Tree Path: [Bypass Sanitization with Clever Markdown](./attack_tree_paths/bypass_sanitization_with_clever_markdown.md)

*   Description: Attackers may craft specific Markdown input that, when processed by Parsedown and subsequently sanitized, still results in exploitable HTML. This often involves finding edge cases or vulnerabilities in the sanitization logic itself.
*   Likelihood: Medium - Attackers are constantly finding new bypasses.
*   Impact: High - Full client-side compromise.
*   Effort: Medium - Requires understanding of sanitization techniques and creative payload crafting.
*   Skill Level: Medium.
*   Detection Difficulty: Hard - Designed to evade detection.

