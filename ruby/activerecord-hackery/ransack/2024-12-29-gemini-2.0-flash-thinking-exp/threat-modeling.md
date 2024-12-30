### High and Critical Ransack Threats

Here are the high and critical threats that directly involve the Ransack gem:

*   **Threat:** Information Disclosure through Unrestricted Search
    *   **Description:** An attacker crafts Ransack queries, potentially through manipulating URL parameters or form inputs, to retrieve data they are not authorized to view. This involves exploiting Ransack's ability to query various model attributes and potentially bypassing intended access controls by constructing specific search conditions.
    *   **Impact:** Exposure of sensitive data, including personal information, financial records, or confidential business data.
    *   **Affected Ransack Component:** Parameter parsing and query building logic.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Carefully define which model attributes are searchable via Ransack using the `searchable_attributes` method.
        *   Implement robust authorization checks *after* the Ransack query is executed to filter results based on the current user's permissions. Do not rely solely on Ransack for authorization.
        *   Consider using virtual attributes or alternative methods for searching on sensitive data that requires stricter access control.

*   **Threat:** Mass Assignment Vulnerability via Ransack Parameters
    *   **Description:** If the application directly uses Ransack parameters to update model attributes without proper filtering, an attacker could potentially modify attributes they shouldn't have access to by including malicious parameters in the search query. This exploits how Ransack parameters are processed and potentially passed to ActiveRecord for updates.
    *   **Impact:** Data corruption, privilege escalation, unauthorized modification of application state.
    *   **Affected Ransack Component:** Parameter handling and interaction with ActiveRecord's mass assignment features.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Utilize strong parameter filtering (e.g., `params.require(:q).permit(...)`) to explicitly define which Ransack parameters are allowed.
        *   Avoid directly using Ransack parameters to update model attributes without explicit whitelisting and validation.