# Attack Tree Analysis for go-martini/martini

Objective: Attacker's Goal: To compromise application that use given project by exploiting weaknesses or vulnerabilities within the project itself.

## Attack Tree Visualization

```
*   **[HIGH-RISK PATH]** Exploit Martini Routing Vulnerabilities
    *   **[HIGH-RISK PATH]** Route Collision/Hijacking
    *   **[HIGH-RISK PATH]** Parameter Injection via Routing
*   **[HIGH-RISK PATH] [CRITICAL NODE]** Exploit Martini Middleware Vulnerabilities
    *   **[HIGH-RISK PATH] [CRITICAL NODE]** Middleware Bypass
    *   **[HIGH-RISK PATH] [CRITICAL NODE]** Vulnerable Martini Middleware
    *   **[CRITICAL NODE]** Middleware Injection/Manipulation
*   **[HIGH-RISK PATH]** Exploit Martini Context Vulnerabilities
    *   **[HIGH-RISK PATH]** Context Data Manipulation
    *   **[HIGH-RISK PATH]** Context Injection
*   **[CRITICAL NODE]** Exploit Martini's Dependency Injection (DI) Mechanism
    *   **[CRITICAL NODE]** Dependency Poisoning
*   **[CRITICAL NODE]** Exploit Martini's Error Handling
    *   **[CRITICAL NODE]** Information Disclosure via Error Pages
```


## Attack Tree Path: [[HIGH-RISK PATH] Exploit Martini Routing Vulnerabilities](./attack_tree_paths/_high-risk_path__exploit_martini_routing_vulnerabilities.md)



## Attack Tree Path: [[HIGH-RISK PATH] Route Collision/Hijacking](./attack_tree_paths/_high-risk_path__route_collisionhijacking.md)



## Attack Tree Path: [[HIGH-RISK PATH] Parameter Injection via Routing](./attack_tree_paths/_high-risk_path__parameter_injection_via_routing.md)



## Attack Tree Path: [[HIGH-RISK PATH] [CRITICAL NODE] Exploit Martini Middleware Vulnerabilities](./attack_tree_paths/_high-risk_path___critical_node__exploit_martini_middleware_vulnerabilities.md)



## Attack Tree Path: [[HIGH-RISK PATH] [CRITICAL NODE] Middleware Bypass](./attack_tree_paths/_high-risk_path___critical_node__middleware_bypass.md)



## Attack Tree Path: [[HIGH-RISK PATH] [CRITICAL NODE] Vulnerable Martini Middleware](./attack_tree_paths/_high-risk_path___critical_node__vulnerable_martini_middleware.md)



## Attack Tree Path: [[CRITICAL NODE] Middleware Injection/Manipulation](./attack_tree_paths/_critical_node__middleware_injectionmanipulation.md)



## Attack Tree Path: [[HIGH-RISK PATH] Exploit Martini Context Vulnerabilities](./attack_tree_paths/_high-risk_path__exploit_martini_context_vulnerabilities.md)



## Attack Tree Path: [[HIGH-RISK PATH] Context Data Manipulation](./attack_tree_paths/_high-risk_path__context_data_manipulation.md)



## Attack Tree Path: [[HIGH-RISK PATH] Context Injection](./attack_tree_paths/_high-risk_path__context_injection.md)



## Attack Tree Path: [[CRITICAL NODE] Exploit Martini's Dependency Injection (DI) Mechanism](./attack_tree_paths/_critical_node__exploit_martini's_dependency_injection__di__mechanism.md)



## Attack Tree Path: [[CRITICAL NODE] Dependency Poisoning](./attack_tree_paths/_critical_node__dependency_poisoning.md)



## Attack Tree Path: [[CRITICAL NODE] Exploit Martini's Error Handling](./attack_tree_paths/_critical_node__exploit_martini's_error_handling.md)



## Attack Tree Path: [[CRITICAL NODE] Information Disclosure via Error Pages](./attack_tree_paths/_critical_node__information_disclosure_via_error_pages.md)



