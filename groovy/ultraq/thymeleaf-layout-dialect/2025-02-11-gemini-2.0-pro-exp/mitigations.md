# Mitigation Strategies Analysis for ultraq/thymeleaf-layout-dialect

## Mitigation Strategy: [Strict Control over Layout and Fragment Names](./mitigation_strategies/strict_control_over_layout_and_fragment_names.md)

1.  **Identify all instances:** Locate all uses of `layout:decorate`, `layout:replace`, `layout:insert`, `th:replace`, and `th:insert` in your Thymeleaf templates.
2.  **Analyze the source:** For each instance, determine *how* the layout/fragment name is being determined. Trace the value back to its origin (controller, database, user input, etc.). Is it hardcoded, or is it dynamic?
3.  **Implement Whitelist/Lookup (for Dynamic Names):**
    *   If the name is *static* (hardcoded string literal directly in the template), no further action is needed for *this specific instance*, but review the overall design for maintainability.
    *   If the name is *dynamic* (constructed in any way, even partially, from a variable or expression), refactor the code to use either a whitelist (enumeration) or a lookup table (map).  *Never* directly use potentially tainted data.
    *   **Whitelist:** Create a `final` class or enum containing all allowed layout/fragment names as *constants*.  Use these constants in your controller logic.  Example:
        ```java
        public final class LayoutNames {
            public static final String ADMIN_LAYOUT = "layouts/admin";
            public static final String USER_LAYOUT = "layouts/user";
            public static final String DEFAULT_LAYOUT = "layouts/default";
            // ... other allowed layouts
        }
        ```
    *   **Lookup Table:** Create a `Map<String, String>` (or use a configuration file, but *not* user-modifiable data) where keys represent a safe, sanitized identifier (e.g., "profilePage", "adminDashboard") and values are the corresponding, pre-approved layout/fragment paths. Example:
        ```java
        Map<String, String> layoutMap = new HashMap<>();
        layoutMap.put("profile", "layouts/profileLayout");
        layoutMap.put("settings", "layouts/settingsLayout");
        // ...
        String requestedPage = ...; // Get a safe key, NOT the raw user input
        String layoutName = layoutMap.getOrDefault(requestedPage, "layouts/defaultLayout");
        ```
4.  **Refactor Controller:** Modify your controller methods to use the whitelist or lookup table to determine the layout/fragment name.  Pass this *safe* name to the Thymeleaf template.  The controller *must* be the gatekeeper.
5.  **Remove Direct Input:** Ensure that *no* user-supplied input (or data derived directly from it without proper sanitization and validation) is ever used in the layout/fragment attribute values.
6. **Avoid Complex Expressions:** Keep expressions within layout attributes simple. Avoid string concatenation or calculations *within the template itself* if any part involves potentially unsafe data. Do all complex logic in the controller.

*   **Threats Mitigated:**
    *   **Server-Side Template Injection (SSTI) (Severity: Critical):** This is the *primary* threat.  By controlling the layout/fragment name, an attacker could inject arbitrary Thymeleaf expressions, potentially leading to Remote Code Execution (RCE).
    *   **Path Traversal (Severity: High):** An attacker might try to include files outside the intended template directory (e.g., `../../etc/passwd`) by manipulating the fragment name.
    *   **Information Disclosure (Severity: Medium):** Even without full SSTI, an attacker might probe for file existence or gain information about the server's file structure.

*   **Impact:**
    *   **SSTI:** Risk reduced from *Critical* to *Negligible* (if implemented correctly). This is the most important mitigation.
    *   **Path Traversal:** Risk reduced from *High* to *Negligible*.
    *   **Information Disclosure:** Risk reduced from *Medium* to *Low*.

*   **Currently Implemented:**
    *   Implemented for the main user profile pages (`ProfileController.java`) using a lookup table.
    *   Implemented for the admin dashboard (`AdminController.java`) using a whitelist (enum).

*   **Missing Implementation:**
    *   Missing in the `ReportController.java`, where the report template is partially determined by a URL parameter. This *must* be refactored to use a lookup table.
    *   Missing in the `SearchController.java` where search result fragments are dynamically included. This *must* be refactored to use a whitelist.

## Mitigation Strategy: [Thorough Code Reviews (Focused on Layout Dialect Usage)](./mitigation_strategies/thorough_code_reviews__focused_on_layout_dialect_usage_.md)

1.  **Establish Code Review Guidelines:** Include *specific* guidelines for reviewing code that uses the Thymeleaf Layout Dialect in your team's code review checklist.
2.  **Focus on Layout Usage:** During code reviews, reviewers *must* specifically:
    *   Identify *all* uses of `layout:decorate`, `layout:replace`, `layout:insert`, `th:replace`, and `th:insert`.
    *   Verify *how* layout and fragment names are determined for *each* instance.
    *   Check for any dynamic logic involved in choosing layouts or fragments.  *Any* dynamic logic is a potential red flag.
    *   Trace the source of *any* data used in layout/fragment attributes back to its origin.
3.  **Check for Whitelists/Lookups:** Verify that whitelists or lookup tables are being used *correctly* and *consistently* to prevent direct use of user input or unsanitized data.
4.  **Review Controller Logic:** Ensure that the controller logic that prepares data for the templates is secure and does not inadvertently introduce vulnerabilities that could be exploited *through* the layout system. The controller is the primary point of defense.
5.  **Document Findings:** Document any potential security issues found during code reviews and ensure they are addressed *before* the code is merged.

*   **Threats Mitigated:**
    *   **All threats related to dynamic layout/fragment inclusion (SSTI, Path Traversal, Information Disclosure) (Severity: Variable):** Code reviews are a *proactive* measure to catch vulnerabilities *before* they are introduced into the codebase.

*   **Impact:**
    *   **All threats:** Risk reduced significantly.  Code reviews are a critical part of a secure development lifecycle.

*   **Currently Implemented:**
    *   Code reviews are part of the development process, but there are *no* specific guidelines for reviewing Thymeleaf Layout Dialect usage.

*   **Missing Implementation:**
    *   Specific code review guidelines for Thymeleaf Layout Dialect *must* be established, documented, and enforced.
    *   Reviewers need to be trained on these guidelines. This is a critical gap.

