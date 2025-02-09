# Attack Surface Analysis for redis/hiredis

## Attack Surface: [Command Injection](./attack_surfaces/command_injection.md)

*   **Description:** Attackers inject malicious Redis commands by manipulating input data that is used to construct Redis commands.
*   **hiredis Contribution:** `hiredis` provides functions for building commands but does *not* automatically sanitize or escape user inputs. The responsibility for safe command construction lies entirely with the developer. Functions like `redisCommand` and `redisvCommand` are particularly susceptible if used directly with unsanitized input.
*   **Example:**
    ```c
    // Vulnerable code:
    char *userInput = get_user_input(); // Assume this gets "mykey; SHUTDOWN"
    redisCommand(context, "DEL %s", userInput);
    ```
*   **Impact:**
    *   Complete compromise of the Redis database.
    *   Execution of arbitrary Redis commands (e.g., `FLUSHALL`, `SHUTDOWN`, `CONFIG SET`).
    *   Data exfiltration.
    *   Denial of service.
    *   Potentially, if Redis is configured to run Lua scripts with elevated privileges, the attacker might gain control of the host system.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Primary: Use `redisCommandArgv` and related functions:** Construct commands using `redisCommandArgv`, `redisAppendCommandArgv`, etc. These functions treat arguments as data, preventing them from being interpreted as command parts. This is the *strongly preferred* method.
        ```c
        // Safer code:
        char *userInput = get_user_input(); // Even if this is "mykey; SHUTDOWN"
        redisCommandArgv(context, 2, (const char*[]){"DEL", userInput}, NULL);
        ```
    *   **Secondary (Highly Discouraged): Input Validation and Sanitization:** Implement *extremely* strict input validation, preferably using whitelists, to allow only known-safe characters and formats.  *Do not rely solely on blacklists.*  This is error-prone and difficult to get right for all possible Redis commands.  Avoid custom escaping; it's a common source of vulnerabilities.

## Attack Surface: [Denial of Service (DoS) via Unhandled Timeouts](./attack_surfaces/denial_of_service__dos__via_unhandled_timeouts.md)

*   **Description:** Attackers cause the Redis server to become unresponsive, and the application using `hiredis` blocks indefinitely, leading to a DoS.
*   **hiredis Contribution:** `hiredis` operations can block if the Redis server is unavailable or slow. Without timeouts, the application can hang.
*   **Example:** A network disruption occurs, and `redisCommand` blocks indefinitely without a timeout set.
*   **Impact:** Application unavailability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Set Timeouts:** Use `redisSetTimeout` to configure timeouts for all `hiredis` operations.  Choose appropriate timeout values based on the expected response times.
    *   **Asynchronous Operations (Consider):** If appropriate for the application, use the `hiredis` asynchronous API to avoid blocking the main thread.

## Attack Surface: [Denial of Service (DoS) via Large Replies](./attack_surfaces/denial_of_service__dos__via_large_replies.md)

*   **Description:** Attackers trigger Redis commands that return extremely large responses, consuming excessive memory in the application and potentially causing a crash.
*   **hiredis Contribution:** `hiredis` allocates memory to store the replies from Redis.  It doesn't inherently limit the size of these replies.
*   **Example:** An attacker populates a Redis list with a massive amount of data, and the application attempts to retrieve the entire list using `LRANGE mylist 0 -1`.
*   **Impact:** Application crash due to out-of-memory errors; denial of service.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Limit Reply Sizes:** Avoid retrieving excessively large data in a single operation.
    *   **Use Chunking/Streaming:** Use Redis commands that allow retrieving data in smaller chunks (e.g., `SCAN` for keys, `LRANGE` with limited ranges for lists).
    *   **Proper `freeReplyObject` Usage:** Always free the memory allocated for `redisReply` objects using `freeReplyObject` after use to prevent memory leaks, which can exacerbate this issue.

