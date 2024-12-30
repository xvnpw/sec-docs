### High and Critical Hanami-Specific Attack Surfaces

*   **Attack Surface:** Unvalidated Action Parameters Leading to Mass Assignment
    *   **Description:** Attackers can manipulate request parameters to modify model attributes they should not have access to, potentially leading to data corruption or privilege escalation.
    *   **How Hanami Contributes to the Attack Surface:** Hanami's action parameters are automatically mapped to the request. If models are directly updated with these parameters without proper filtering or whitelisting, it can lead to mass assignment vulnerabilities.
    *   **Impact:** Data corruption, unauthorized data modification, privilege escalation.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use Strong Parameter Filtering/Whitelisting:** Explicitly define which parameters are allowed to be used for updating models within the action.
        *   **Avoid Direct Model Updates with Request Parameters:** Use dedicated methods or data transfer objects (DTOs) to handle parameter mapping and validation before updating models.
        *   **Implement Authorization Checks:** Ensure that users are authorized to modify the specific attributes they are attempting to change.