# Threat Model Analysis for usememos/memos

## Threat: [Unintended Public Disclosure of Private Memos](./threats/unintended_public_disclosure_of_private_memos.md)

*   **Description:** An attacker might exploit a user's misunderstanding of the visibility settings, potentially through social engineering or by gaining temporary access to an unlocked device, to change a memo's visibility to "Public" or a less secure setting.  The attacker could also try to guess default passwords if used for "Protected" memos. The core issue is the memo's visibility state being changed against the user's actual intent.
*   **Impact:** Leakage of sensitive personal information, confidential data, or internal communications, leading to reputational damage, financial loss, or legal consequences.
*   **Affected Component:** `api/memo.go` (visibility setting logic), `web/src/components/MemoContent.tsx` (UI for displaying and setting visibility), `store/db/sqlite/memo.go` (database interaction for visibility).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **UI/UX Improvements:** Implement a very clear visual distinction between visibility states (large icons, contrasting colors, explicit labels).
    *   **Confirmation Dialogs:** Require explicit confirmation *before* changing a memo from "Private" to any other visibility level, clearly stating the consequences.
    *   **Default to Private:** Ensure the default visibility for new memos is "Private" (configurable by admins, but strongly recommended).
    *   **User Education:** Provide in-app tutorials or tooltips explaining visibility settings.
    *   **Audit Logging:** Log all changes to memo visibility.
    *   **Session Timeout:** Implement a reasonable session timeout.
    *   **Strong Password for Protected:** If "Protected" uses a password, enforce strong password requirements.

## Threat: [Data Exfiltration via Malicious Memo Content (Stored XSS)](./threats/data_exfiltration_via_malicious_memo_content__stored_xss_.md)

*   **Description:** An attacker creates a memo containing malicious JavaScript code. When another user views this memo, the attacker's code executes within their browser, potentially stealing cookies, session tokens, or redirecting them to a malicious website. This is a *stored* XSS attack, and the malicious code resides *within the memo itself*.
*   **Impact:** Session hijacking, theft of user credentials, redirection to malicious websites, defacement, data exfiltration.  The attacker can potentially gain control of other users' accounts *through the memo*.
*   **Affected Component:** `web/src/components/MemoContent.tsx` (memo rendering), `pkg/parser/parser.go` (memo content parsing), `api/memo.go` (memo saving and retrieval).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Robust Input Sanitization:** Use a well-vetted HTML sanitization library (e.g., DOMPurify) to remove all dangerous HTML tags and attributes from memo content *before* database storage. This is the *primary* defense.
    *   **Content Security Policy (CSP):** Implement a strict CSP that disallows inline scripts (`script-src 'self'`) and restricts script sources. This is a strong *secondary* defense.
    *   **Output Encoding:** Ensure proper encoding when displaying memo content (a fallback defense, *not* primary).
    *   **Regular Expression Review:** Carefully review any regular expressions used for input validation.
    *   **Testing:** Thoroughly test with various XSS payloads.

## Threat: [Bypassing Visibility Controls (Authorization Bypass)](./threats/bypassing_visibility_controls__authorization_bypass_.md)

*   **Description:** An attacker directly manipulates API requests or exploits a flaw in the authorization logic *specifically related to memo access* to view memos they should not have access to (e.g., private memos of other users). This is *not* a general account takeover, but a direct bypass of the memo visibility controls.
*   **Impact:** Unauthorized access to private or protected memos, leading to data breaches and privacy violations. The attacker gains access to content they are explicitly not authorized to see.
*   **Affected Component:** `api/memo.go` (API endpoints for memo access), `store/db/sqlite/memo.go` (database queries for memo retrieval), `api/auth.go` (authentication and authorization logic *as it relates to memo access*).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Server-Side Authorization Checks:** Implement robust authorization checks on the *server-side* for *every* API request that accesses or modifies memos. *Never* rely on client-side checks.
    *   **Parameterized Queries:** Use parameterized queries (prepared statements) for all database interactions to prevent SQL injection.
    *   **Object-Level Permissions:** Ensure authorization checks are performed for *each individual memo*, not just at the endpoint level.
    *   **Session Management:** Use a secure session management mechanism.
    *   **Testing:** Thoroughly test all API endpoints with invalid and unauthorized requests.

## Threat: [Account Takeover via Weak Tag/Search Functionality (Injection)](./threats/account_takeover_via_weak_tagsearch_functionality__injection_.md)

* **Description:**  An attacker crafts a malicious search query or tag that exploits a vulnerability (e.g., SQL injection) in the search/tag processing.  Crucially, this threat is only included here if the vulnerability allows the attacker to *access or modify memos belonging to other users*, making it a direct memo-related threat. If the injection only affects the attacker's own account or data, it's not included in this filtered list.
* **Impact:**  Data breaches (reading, modifying, or deleting *other users'* memos), unauthorized access to memos, potential for server-side code execution (if the injection is severe enough).
* **Affected Component:** `api/memo.go` (search and tag API endpoints), `store/db/sqlite/memo.go` (search and tag database queries), `pkg/parser/parser.go` (query parsing).
* **Risk Severity:** Critical
* **Mitigation Strategies:**
    *   **Parameterized Queries:** Use parameterized queries (prepared statements) for *all* database interactions related to search and tags.
    *   **Input Validation and Sanitization:** Strictly validate and sanitize all user input in search queries and tag names (whitelist approach).
    *   **ORM (Object-Relational Mapper):** Consider using a well-vetted ORM.
    *   **Rate Limiting:** Implement rate limiting on search requests.
    *   **Testing:** Thoroughly test with various injection payloads.

