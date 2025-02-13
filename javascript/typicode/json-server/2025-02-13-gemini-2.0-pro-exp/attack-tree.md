# Attack Tree Analysis for typicode/json-server

Objective: Unauthorized Data Access/Modification OR Arbitrary Code Execution on Server

## Attack Tree Visualization

                                     +-------------------------------------------------+
                                     |  Attacker's Goal: Unauthorized Data Access/Modification  |
                                     |  OR Arbitrary Code Execution on Server          |
                                     +-------------------------------------------------+
                                                        |
          +----------------------------------------------------------------------------+
          |                                                                            |
+-------------------------+                                      +---------------------+
|  1. Abuse of           |                                      |  2. Exploitation of |
|     Default Routes/Features [HIGH-RISK] |                       |     Vulnerable      |
|                                         |                       |     Dependencies    |
+-------------------------+                                      +---------------------+
          |                                                                  |
+---------+---------+                                      +-------------+-------------+
| 1.a.    | 1.b.    |                                      | 2.a.        | 2.b.        |
|  Access |  Modify |                                      |  Known CVE  |  0-day in   |
|  /db    |  Data   |                                      |  in a      |  a used     |
|  (Read) |  via    |                                      |  json-     |  dependency |
| [CRITICAL]|  Default|                                      |  server    |  (e.g.,    |
|         |  Routes |                                      |  dep.      |  Express   |
|         |  (POST, |                                      | [HIGH-RISK]|  middleware)|
|         |  PUT,   |                                      |             | [CRITICAL]  |
|         |  PATCH, |                                      |             |             |
|         |  DELETE)|                                      |             |             |
|         |[CRITICAL]|                                      |             |             |
+---------+---------+                                      +-------------+-------------+
                                                                              |
                                                                  +-------------+
                                                                  | 2.d         |
                                                                  |  RCE via   |
                                                                  |  Vulnerable|
                                                                  |  Dependency|
                                                                  | [CRITICAL]  |
                                                                  +-------------+

## Attack Tree Path: [1. Abuse of Default Routes/Features [HIGH-RISK]](./attack_tree_paths/1__abuse_of_default_routesfeatures__high-risk_.md)

This is a high-risk area because `json-server`'s default behavior, if not explicitly secured, exposes significant vulnerabilities.  The ease of exploitation makes these attacks very likely.

## Attack Tree Path: [1.a. Access /db (Read) [CRITICAL]](./attack_tree_paths/1_a__access_db__read___critical_.md)

*   **Description:**  Directly accessing the `/db` endpoint provides the attacker with the *entire* JSON database content.  This is a complete data breach.
*   **Likelihood:** High (if `/db` is exposed)
*   **Impact:** Very High (full data exposure)
*   **Effort:** Very Low (typing a URL)
*   **Skill Level:** Novice
*   **Detection Difficulty:** Medium (appears in logs, but may be missed without active monitoring)
*   **Mitigation:**  Disable the `/db` route entirely in production.  Serve data only through the API routes.

## Attack Tree Path: [1.b. Modify Data via Default Routes (POST, PUT, PATCH, DELETE) [CRITICAL]](./attack_tree_paths/1_b__modify_data_via_default_routes__post__put__patch__delete___critical_.md)

*   **Description:**  Using standard HTTP methods (POST, PUT, PATCH, DELETE) on the default resource routes (e.g., `/posts`, `/comments`), an attacker can create, update, or delete data without any authentication or authorization.
*   **Likelihood:** High (if routes are unprotected)
*   **Impact:** High (data corruption, deletion, unauthorized creation)
*   **Effort:** Low (using standard HTTP methods)
*   **Skill Level:** Novice
*   **Detection Difficulty:** Medium (appears in logs, but unauthorized changes may be missed without active monitoring)
*   **Mitigation:** Implement robust authentication and authorization middleware to protect *all* routes that modify data.

## Attack Tree Path: [2. Exploitation of Vulnerable Dependencies](./attack_tree_paths/2__exploitation_of_vulnerable_dependencies.md)

This category covers attacks that leverage vulnerabilities within `json-server` itself or, more commonly, its dependencies (like Express.js).

## Attack Tree Path: [2.a. Known CVE in a `json-server` dependency [HIGH-RISK]](./attack_tree_paths/2_a__known_cve_in_a__json-server__dependency__high-risk_.md)

*   **Description:**  Exploiting a publicly known vulnerability (CVE) in one of `json-server`'s dependencies.  Exploit code is often readily available.
*   **Likelihood:** Medium (depends on dependency versions and patching)
*   **Impact:** Medium to Very High (depends on the specific CVE)
*   **Effort:** Low to Medium (exploit code may be public)
*   **Skill Level:** Intermediate to Advanced (depends on exploit complexity)
*   **Detection Difficulty:** Medium to Hard (requires vulnerability scanning and IDS)
*   **Mitigation:**  Keep all dependencies updated to the latest versions. Use dependency scanning tools (e.g., `npm audit`, `yarn audit`).

## Attack Tree Path: [2.b. 0-day in a used dependency [CRITICAL]](./attack_tree_paths/2_b__0-day_in_a_used_dependency__critical_.md)

*   **Description:**  Exploiting a previously unknown vulnerability (a "zero-day") in a dependency.  This is much less likely but extremely dangerous.
*   **Likelihood:** Very Low
*   **Impact:** Very High (could lead to RCE or complete compromise)
*   **Effort:** Very High (requires discovering and exploiting the vulnerability)
*   **Skill Level:** Expert
*   **Detection Difficulty:** Very Hard (zero-days are unknown by definition)
*   **Mitigation:**  Have a robust incident response plan. Monitor security advisories.  Consider using a Web Application Firewall (WAF).

## Attack Tree Path: [2.d. RCE via Vulnerable Dependency [CRITICAL]](./attack_tree_paths/2_d__rce_via_vulnerable_dependency__critical_.md)

*   **Description:** A vulnerability in dependency that allows Remote Code Execution.
*   **Likelihood:** Low
*   **Impact:** Very High (complete system compromise)
*   **Effort:** Medium to High
*   **Skill Level:** Advanced to Expert
*   **Detection Difficulty:** Hard
*   **Mitigation:** Keep all dependencies updated. Use a WAF. Implement strong server security practices.

