# Attack Tree Analysis for wg/wrk

Objective: Compromising Application via wrk

## Attack Tree Visualization

```
- Compromise Application via wrk **[CRITICAL NODE]**
  - Exploit wrk's Request Generation Capabilities **[CRITICAL NODE]** **[HIGH-RISK PATH START]**
    - Send Malicious HTTP Requests **[CRITICAL NODE]** **[HIGH-RISK PATH START]**
      - Inject Malicious Headers **[CRITICAL NODE]** **[HIGH-RISK PATH START]**
        - Large Header Values **[HIGH-RISK PATH]**
        - Manipulate Content-Type **[CRITICAL NODE]** **[HIGH-RISK PATH]**
      - Send Requests with Malicious Body **[CRITICAL NODE]** **[HIGH-RISK PATH START]**
        - Large Request Body **[HIGH-RISK PATH]**
        - Unexpected Data Formats **[HIGH-RISK PATH]**
      - Send Requests with Malicious URLs **[CRITICAL NODE]** **[HIGH-RISK PATH START]**
        - Path Traversal Attempts **[CRITICAL NODE]** **[HIGH-RISK PATH]**
    - Exploit wrk's Concurrency and Load Generation **[CRITICAL NODE]** **[HIGH-RISK PATH START]**
      - Launch Denial of Service (DoS) Attacks **[CRITICAL NODE]** **[HIGH-RISK PATH]**
  - Exploit wrk's Configuration Options
    - Configure Excessive Connections/Threads **[CRITICAL NODE]** **[HIGH-RISK PATH]**
```


## Attack Tree Path: [Large Header Values](./attack_tree_paths/large_header_values.md)

Exploit wrk's Request Generation Capabilities -> Send Malicious HTTP Requests -> Inject Malicious Headers -> Large Header Values

## Attack Tree Path: [Manipulate Content-Type](./attack_tree_paths/manipulate_content-type.md)

Exploit wrk's Request Generation Capabilities -> Send Malicious HTTP Requests -> Inject Malicious Headers -> Manipulate Content-Type

## Attack Tree Path: [Large Request Body](./attack_tree_paths/large_request_body.md)

Exploit wrk's Request Generation Capabilities -> Send Malicious HTTP Requests -> Send Requests with Malicious Body -> Large Request Body

## Attack Tree Path: [Unexpected Data Formats](./attack_tree_paths/unexpected_data_formats.md)

Exploit wrk's Request Generation Capabilities -> Send Malicious HTTP Requests -> Send Requests with Malicious Body -> Unexpected Data Formats

## Attack Tree Path: [Path Traversal Attempts](./attack_tree_paths/path_traversal_attempts.md)

Exploit wrk's Request Generation Capabilities -> Send Malicious HTTP Requests -> Send Requests with Malicious URLs -> Path Traversal Attempts

## Attack Tree Path: [Launch Denial of Service (DoS) Attacks](./attack_tree_paths/launch_denial_of_service__dos__attacks.md)

Exploit wrk's Concurrency and Load Generation -> Launch Denial of Service (DoS) Attacks

## Attack Tree Path: [Configure Excessive Connections/Threads](./attack_tree_paths/configure_excessive_connectionsthreads.md)

Exploit wrk's Configuration Options -> Configure Excessive Connections/Threads

