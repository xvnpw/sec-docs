# Attack Surface Analysis for ljharb/qs

## Attack Surface: [Denial of Service (DoS) via Complex or Deeply Nested Objects](./attack_surfaces/denial_of_service__dos__via_complex_or_deeply_nested_objects.md)

*   **Description:** An attacker sends a query string with excessively deep or complex nested objects and arrays, causing the server to consume excessive resources (CPU, memory) during parsing.
    *   **How `qs` Contributes:** `qs` is designed to parse nested structures. Without proper limits, it will attempt to parse arbitrarily complex nesting, potentially leading to resource exhaustion.
    *   **Example:** `?a[b][c][d][e][f][g][h][i][j][k][l][m][n][o][p][q][r][s][t][u][v][w][x][y][z]=value`
    *   **Impact:** Server overload, application slowdown, potential crashes, inability to serve legitimate requests.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Configure `qs` with options to limit the depth of parsing (e.g., `parameterLimit`, `depth`).
        *   Implement request size limits at the web server or application level.

## Attack Surface: [Prototype Pollution](./attack_surfaces/prototype_pollution.md)

*   **Description:** An attacker crafts a specific query string that injects properties into the `Object.prototype`, potentially affecting the behavior of the entire application.
    *   **How `qs` Contributes:** Older versions of `qs` (and potentially configurations allowing it) can be vulnerable to prototype pollution by parsing keys like `__proto__` or `constructor.prototype`.
    *   **Example:** `?__proto__[isAdmin]=true` or `?constructor[prototype][isAdmin]=true`
    *   **Impact:** Bypassing security checks, unexpected application behavior, potential remote code execution in specific scenarios (though less direct through `qs`).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Upgrade `qs` to the latest version:** Modern versions of `qs` have mitigations against prototype pollution.
        *   **Configure `qs` with `allowPrototypes: false`:** This option prevents parsing of `__proto__` and `constructor` properties.

## Attack Surface: [Resource Exhaustion via Large Payloads](./attack_surfaces/resource_exhaustion_via_large_payloads.md)

*   **Description:** An attacker sends an extremely long query string, causing the server to allocate excessive memory to process it, potentially leading to resource exhaustion.
    *   **How `qs` Contributes:** `qs` needs to allocate memory to store and process the parsed query string. Very long strings can consume significant resources.
    *   **Example:** `?` followed by thousands of characters forming a long parameter or many parameters.
    *   **Impact:** Server overload, application slowdown, potential crashes, inability to serve legitimate requests.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement request size limits at the web server or application level.
        *   Configure `qs`'s `parameterLimit` option to restrict the number of parameters parsed.

