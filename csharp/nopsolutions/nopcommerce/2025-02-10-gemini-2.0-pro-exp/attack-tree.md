# Attack Tree Analysis for nopsolutions/nopcommerce

Objective: [[Gain Unauthorized Administrative Access]]

## Attack Tree Visualization

[[Gain Unauthorized Administrative Access]]
      /               \
     /                 \
[[Exploit Plugin]]     [Exploit Core Functionality]
[Vulnerabilities]]             |
      |                      |
      |
      |       [Exploit Deserialization Vulnerabilities]
      |                      |
      |                      |
[[Known Plugin]]     [Unsafe Use of ObjectDataProvider]
[[Vulnerability]]
      |
      |
[[Unpatched Plugin]]
[[Vulnerability]]
      |
      |
     /
    /
[Abuse nopCommerce Features]
    |
    |
[Misconfigured Permissions]

## Attack Tree Path: [Path 1: Exploit Known Plugin Vulnerability](./attack_tree_paths/path_1_exploit_known_plugin_vulnerability.md)

`[[Gain Unauthorized Administrative Access]]` -> `[[Exploit Plugin Vulnerabilities]]` -> `[[Known Plugin Vulnerability]]`

## Attack Tree Path: [Path 2: Exploit Unpatched Plugin Vulnerability](./attack_tree_paths/path_2_exploit_unpatched_plugin_vulnerability.md)

`[[Gain Unauthorized Administrative Access]]` -> `[[Exploit Plugin Vulnerabilities]]` -> `[[Unpatched Plugin Vulnerability]]`

## Attack Tree Path: [Path 3: Exploit Deserialization Vulnerability](./attack_tree_paths/path_3_exploit_deserialization_vulnerability.md)

`[[Gain Unauthorized Administrative Access]]` -> `[Exploit Core Functionality]` -> `[Exploit Deserialization Vulnerabilities]` -> `[Unsafe Use of ObjectDataProvider]`

## Attack Tree Path: [Path 4: Abuse Misconfigured Permissions](./attack_tree_paths/path_4_abuse_misconfigured_permissions.md)

`[[Gain Unauthorized Administrative Access]]` -> `[Abuse nopCommerce Features]` -> `[Misconfigured Permissions]`

