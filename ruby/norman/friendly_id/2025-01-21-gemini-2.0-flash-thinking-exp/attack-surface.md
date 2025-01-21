# Attack Surface Analysis for norman/friendly_id

## Attack Surface: [Malicious Content in Slugs](./attack_surfaces/malicious_content_in_slugs.md)

* **Description:** User-provided data used to generate slugs can contain malicious content (e.g., JavaScript for XSS).
* **How friendly_id Contributes:** `friendly_id` uses attributes of the model to generate slugs. If these attributes are user-controlled and not sanitized, the malicious content becomes part of the slug.
* **Example:** A user creates a blog post with a title like `<script>alert("XSS")</script>My Awesome Post`. `friendly_id` generates a slug containing this script. When the slug is displayed in a link or elsewhere without proper encoding, the script executes.
* **Impact:** Cross-Site Scripting (XSS), leading to session hijacking, cookie theft, redirection to malicious sites, or defacement.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * Sanitize input data before using it for slug generation. Use methods like `strip_tags` or a dedicated sanitization library.
    * Encode slugs when displaying them in HTML contexts. Use Rails' `sanitize` or `html_escape` helpers.

