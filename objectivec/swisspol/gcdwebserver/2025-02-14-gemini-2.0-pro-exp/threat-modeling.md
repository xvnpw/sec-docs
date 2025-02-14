# Threat Model Analysis for swisspol/gcdwebserver

## Threat: [Denial of Service (DoS) via Slow Connections (Slowloris)](./threats/denial_of_service__dos__via_slow_connections__slowloris_.md)

*   **Threat:** Denial of Service (DoS) via Slow Connections (Slowloris) - *If GCDWebServer's built-in timeouts are misconfigured or insufficient.*

    *   **Description:** An attacker opens numerous connections but sends data very slowly, exhausting server resources. While application-level mitigation is *best*, GCDWebServer's own timeout settings are a first line of defense. If these are set too high (or not at all), GCDWebServer itself becomes vulnerable.
    *   **Impact:** Denial of service, making the application unavailable.
    *   **Affected GCDWebServer Component:** `GCDWebServerConnection` and the overall connection handling within `GCDWebServer`. Specifically, the `connectedTimeout`, `readTimeout`, and `writeTimeout` properties (or their configuration equivalents) are crucial.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        *   **Configure Timeouts:** Ensure that `connectedTimeout`, `readTimeout`, and `writeTimeout` are set to reasonably short values within GCDWebServer's configuration. This is a *direct* GCDWebServer configuration issue. The specific values depend on the application's needs, but should be as short as practically possible. This is the *primary* mitigation at the GCDWebServer level. *Application-level* mitigations are still recommended as a second layer of defense.

## Threat: [Denial of Service (DoS) via Large Request Bodies](./threats/denial_of_service__dos__via_large_request_bodies.md)

*   **Threat:** Denial of Service (DoS) via Large Request Bodies - *If GCDWebServer doesn't provide any built-in limits and relies entirely on the application.*

    *   **Description:** An attacker sends a request with a very large body, consuming excessive server resources. While the *application* should enforce limits, if GCDWebServer itself has *no* built-in protection against extremely large requests, it could be directly vulnerable. *This depends on the specific implementation details of GCDWebServer and how it buffers incoming data.*
    *   **Impact:** Denial of service, potentially crashing the server.
    *   **Affected GCDWebServer Component:** `GCDWebServerRequest` and its subclasses (how they handle incoming data streams). The core question is whether GCDWebServer buffers the *entire* request body before handing it to the application, or if it provides a streaming mechanism.
    *   **Risk Severity:** High.
    *   **Mitigation Strategies:**
        * **Verify GCDWebServer Behavior:** Carefully examine GCDWebServer's documentation and source code to determine how it handles large request bodies. Does it have *any* built-in limits or buffering behavior that could be exploited?
        * **If No Built-in Limits:** If GCDWebServer provides *no* inherent protection, the *application* is *entirely* responsible for implementing size limits and streaming. This threat then moves to the application-level threat list.
        * **If Built-in Limits Exist:** If GCDWebServer *does* have some form of built-in buffering or size limits, ensure these are configured appropriately (and are not excessively large). This would be a direct GCDWebServer configuration issue.

## Threat: [Running with Excessive Privileges (e.g., Root)](./threats/running_with_excessive_privileges__e_g___root_.md)

*   **Threat:** Running with Excessive Privileges (e.g., Root) - *Directly impacts the severity of *any* GCDWebServer vulnerability.*

    *   **Description:** The application (and therefore GCDWebServer) runs as root. This is *not* a GCDWebServer vulnerability itself, but it *drastically* increases the impact of *any* other vulnerability within GCDWebServer.
    *   **Impact:** System compromise if *any* GCDWebServer vulnerability is exploited.
    *   **Affected GCDWebServer Component:** N/A - This is an OS-level and application deployment issue. However, it *directly* affects the severity of all other GCDWebServer threats.
    *   **Risk Severity:** Critical.
    *   **Mitigation Strategies:**
        *   **Least Privilege:** *Never* run the application (and thus GCDWebServer) as root. Use a dedicated, unprivileged user account. This is a fundamental security principle.

