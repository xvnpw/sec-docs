# Threat Model Analysis for sj26/mailcatcher

## Threat: [Unauthenticated Web UI Access](./threats/unauthenticated_web_ui_access.md)

*   **Description:** An attacker on the same network as Mailcatcher can access the web interface (default port 1080) without any authentication. They can browse, read, and potentially download all captured emails by simply navigating to the Mailcatcher server's IP address and port in a web browser.
*   **Impact:** Confidentiality breach. Sensitive information within emails (credentials, secrets, personal data) is exposed to unauthorized individuals on the network.
*   **Affected Component:** Web UI (Ruby Sinatra application)
*   **Risk Severity:** High (in shared development environments or if network access is not properly controlled)
*   **Mitigation Strategies:**
    *   Network Segmentation: Isolate Mailcatcher to a dedicated and secured development network.
    *   Network Access Control: Implement strict firewall rules or Network Access Control Lists (ACLs) to restrict access to the web UI port (1080) to only authorized IPs or networks.
    *   Avoid Sending Sensitive Data: Absolutely avoid sending real production data or sensitive personal information through Mailcatcher. Use only anonymized or synthetic test data.
    *   Regularly Clear Emails: Implement an automated process or policy to periodically and frequently delete captured emails from Mailcatcher.

## Threat: [Unauthenticated API Access](./threats/unauthenticated_api_access.md)

*   **Description:** Similar to the web UI, the Mailcatcher API (e.g., `/messages.json`) is accessible without authentication. An attacker can programmatically access and download all captured emails using HTTP requests to the API endpoints. This allows for automated and potentially large-scale exfiltration of sensitive data.
*   **Impact:** Confidentiality breach. Sensitive information within emails can be easily and automatically extracted, potentially leading to large-scale data leaks.
*   **Affected Component:** API (Ruby Sinatra application, specifically API endpoints)
*   **Risk Severity:** High (in shared development environments or if the API port is exposed and accessible)
*   **Mitigation Strategies:**
    *   Network Segmentation: Isolate Mailcatcher to a dedicated and secured development network.
    *   Network Access Control: Implement strict firewall rules or Network Access Control Lists (ACLs) to restrict access to the API port (typically same as web UI port 1080) to only authorized IPs or networks.
    *   Avoid Exposing API Port: Ensure the API port is not publicly accessible, especially if Mailcatcher is running on a shared development server.
    *   Regularly Clear Emails: Implement an automated process or policy to periodically and frequently delete captured emails from Mailcatcher.

