# Attack Tree Analysis for wg/wrk

Objective: To cause a Denial of Service (DoS) or Resource Exhaustion on the target application, leveraging `wrk`'s capabilities or misconfigurations.

## Attack Tree Visualization

```
                                      [DoS/Resource Exhaustion via wrk]*
                                                  |
                      -----------------------------------------------------------------
                      |                                                               |
        [High Volume Request Flood]*                                    [Exploit Application Logic via Scripting]
                      |
        **==============================**                              -----------------------------------------
        |             |              |                                              |
[Many Connections]* [High Throughput]* [Long Duration]                               [Target Inefficient Code]
                                     |                                              |
                            **[No Rate Limits]***                                 [Known Slow Endpoints]*

```

## Attack Tree Path: [High-Risk Path 1: High Volume Request Flood](./attack_tree_paths/high-risk_path_1_high_volume_request_flood.md)

*   **Overall Description:** This attack path focuses on overwhelming the target application with a massive number of requests, exceeding its capacity to handle them. `wrk` is used as the tool to generate this high volume of traffic.

*   **Critical Nodes:**
    *   **[DoS/Resource Exhaustion via wrk]***: The ultimate goal of the attacker.
    *   **[High Volume Request Flood]***: The primary method used in this attack path.
    *   **[Many Connections]***: Achieved using `wrk`'s `-c` option. A large number of concurrent connections are established to the target.
    *   **[High Throughput]***: Achieved using `wrk`'s `-t` option. A high number of threads are used to generate requests rapidly.
    *   **[Long Duration]**: Achieved using `wrk`'s `-d` option. The attack is sustained for an extended period.
    *   **[No Rate Limits]***: This is a *critical vulnerability* in the target application. The absence of rate limiting allows the attacker to send an unlimited number of requests without being throttled.

*   **Attack Steps and Details:**

    *   **Step 1: Configure `wrk` for High Volume.**
        *   The attacker sets the `-c` (connections) option to a high value (e.g., hundreds or thousands).
        *   The attacker sets the `-t` (threads) option to a high value, maximizing the request generation rate.
        *   The attacker sets the `-d` (duration) option to a long duration (e.g., minutes or hours).
    *   **Step 2: Launch the Attack.**
        *   The attacker runs `wrk` against the target application's URL.
    *   **Step 3: Exploit Lack of Rate Limiting.**
        *   Because the target application has no (or insufficient) rate limiting, the flood of requests overwhelms its resources (CPU, memory, network bandwidth, database connections).
    *   **Step 4: Achieve Denial of Service.**
        *   The application becomes unresponsive or crashes, resulting in a denial of service for legitimate users.

## Attack Tree Path: [High-Risk Path 2: Exploiting Known Slow Endpoints](./attack_tree_paths/high-risk_path_2_exploiting_known_slow_endpoints.md)

*   **Overall Description:** This attack path targets specific parts of the application that are known to be slow or resource-intensive. By repeatedly requesting these endpoints, the attacker can cause resource exhaustion even with a relatively lower volume of requests compared to a brute-force flood.

*   **Critical Nodes:**
    *   **[DoS/Resource Exhaustion via wrk]***: The ultimate goal of the attacker.
    *   **[Exploit Application Logic via Scripting]**: The general approach of using `wrk`'s scripting to target specific vulnerabilities.
    *   **[Target Inefficient Code]**: The strategy of focusing on slow or resource-intensive parts of the application.
    *   **[Known Slow Endpoints]***: Specific URLs or application functions that are known to be performance bottlenecks.

*   **Attack Steps and Details:**

    *   **Step 1: Reconnaissance and Identification.**
        *   The attacker performs reconnaissance on the target application to identify slow endpoints. This might involve:
            *   Using browser developer tools to observe network requests and response times.
            *   Using application performance monitoring (APM) tools (if they have access).
            *   Analyzing publicly available information or documentation.
            *   Testing different parts of the application to find slow-responding areas.
    *   **Step 2: Craft a `wrk` Lua Script (Optional but Enhances Attack).**
        *   The attacker writes a Lua script (`-s` option in `wrk`) to specifically target the identified slow endpoints.
        *   The script might:
            *   Repeatedly request the slow endpoint.
            *   Include specific parameters or data that are known to trigger slow processing.
            *   Customize headers or cookies to further exploit the vulnerability.
    *   **Step 3: Launch the Attack.**
        *   The attacker runs `wrk`, either with the custom Lua script or simply targeting the slow endpoint directly using the URL.
    *   **Step 4: Cause Resource Exhaustion.**
        *   The repeated requests to the slow endpoint consume a disproportionate amount of server resources.
    *   **Step 5: Achieve Denial of Service.**
        *   The application becomes unresponsive or crashes due to resource exhaustion, leading to a denial of service.

