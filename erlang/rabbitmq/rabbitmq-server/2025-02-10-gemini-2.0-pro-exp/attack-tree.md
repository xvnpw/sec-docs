# Attack Tree Analysis for rabbitmq/rabbitmq-server

Objective: Disrupt, Exfiltrate, or Control Application via RabbitMQ Exploitation {CRITICAL}

## Attack Tree Visualization

+-------------------------------------------------+
|  Disrupt, Exfiltrate, or Control Application    |
|  via RabbitMQ Exploitation                      |
+-------------------------------------------------+ {CRITICAL}
      /                                           \
     /
+-----------+-----+                         +-----------+----+
| Resource  |        [HIGH RISK]              |  Default/ |     [HIGH RISK]
| Exhaustion |                                 |  Weak     |
| [HIGH RISK]|                                 |  Creds    |
+-----------+-----+                         +-----------+-----+ {CRITICAL}
     |
     |
+----+----+                                   +----+----+
|  Memory |
|  Exh.  |                                   |  Guess  |
|  (Disk  |                                   |  Creds  |
|  Full)  |                                   | [HIGH RISK]|
| [HIGH RISK]|
+----+----+
     |
     |
+----+----+
|  Disk  |
|  I/O   |
|  Exh.  |
| [HIGH RISK]|
+----+----+

+-----------+-----+
|  Leaked    |
|  Messages  |
|            |
+-----------+-----+
     |
     |
+----+----+
|  Sniff  |
|  Traffic|
| [HIGH RISK]|
|  (No TLS)|
+----+----+

## Attack Tree Path: [Resource Exhaustion [HIGH RISK]](./attack_tree_paths/resource_exhaustion__high_risk_.md)

*   **Overall Description:** This attack vector aims to make the RabbitMQ server unavailable by consuming its resources. It's considered high-risk due to its relative ease of execution and high impact (service disruption).
*   **Specific Attack Steps:**
    *   **Memory Exhaustion (Disk Full) [HIGH RISK]:**
        *   *Description:* The attacker sends a large number of messages, creates many queues/exchanges, or triggers excessive logging, causing RabbitMQ to consume all available memory or disk space. This leads to crashes or unresponsiveness.
        *   *Likelihood:* Medium
        *   *Impact:* High
        *   *Effort:* Low
        *   *Skill Level:* Intermediate
        *   *Detection Difficulty:* Medium
    *   **Disk I/O Exhaustion [HIGH RISK]:**
        *   *Description:* The attacker overwhelms the disk I/O by publishing messages at a very high rate, making RabbitMQ slow or unresponsive.
        *   *Likelihood:* Medium
        *   *Impact:* High
        *   *Effort:* Low
        *   *Skill Level:* Intermediate
        *   *Detection Difficulty:* Medium

## Attack Tree Path: [Default/Weak Credentials [HIGH RISK] {CRITICAL}](./attack_tree_paths/defaultweak_credentials__high_risk__{critical}.md)

*   **Overall Description:** This attack vector exploits the use of default or easily guessable credentials to gain unauthorized access to the RabbitMQ server. It's critical and high-risk because it's a common vulnerability that grants complete control.
*   **Specific Attack Steps:**
    *   **Guess Credentials [HIGH RISK]:**
        *   *Description:* The attacker attempts to guess the username and password for the RabbitMQ server, often trying common defaults like "guest/guest".
        *   *Likelihood:* Medium
        *   *Impact:* Very High
        *   *Effort:* Low
        *   *Skill Level:* Novice
        *   *Detection Difficulty:* Medium

## Attack Tree Path: [Leaked Messages](./attack_tree_paths/leaked_messages.md)

* **Overall Description:** This attack vector aims to intercept messages in transit.
* **Specific Attack Steps:**
    *  **Sniff Network Traffic [HIGH RISK] (No TLS):**
        *   *Description:* If TLS encryption is *not* used for the connection between clients and the RabbitMQ server, an attacker on the same network (or with access to network infrastructure) can capture the raw network traffic and extract the messages.
        *   *Likelihood:* Low (assuming TLS is *usually* used, but High if it's not)
        *   *Impact:* High
        *   *Effort:* Medium
        *   *Skill Level:* Intermediate
        *   *Detection Difficulty:* Hard

