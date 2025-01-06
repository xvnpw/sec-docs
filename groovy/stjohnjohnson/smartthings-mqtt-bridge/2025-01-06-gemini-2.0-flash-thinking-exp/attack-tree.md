# Attack Tree Analysis for stjohnjohnson/smartthings-mqtt-bridge

Objective: Gain Unauthorized Control of SmartThings Devices via Compromised Bridge

## Attack Tree Visualization

```
* Gain Unauthorized Control of SmartThings Devices via Compromised Bridge [CRITICAL NODE]
    * Compromise MQTT Broker [CRITICAL NODE]
        * Gain Unauthorized Access to MQTT Broker
            * Exploit Weak/Default Credentials
                * Guess Common Passwords
                * Brute-force Credentials
        * Inject Malicious MQTT Messages
            * Publish Crafted Control Messages
                * Reverse Engineer Topic Structure
                * Inject Commands to Control Devices Directly
    * Exploit Insecure Configuration [CRITICAL NODE]
        * Access Configuration Files with Sensitive Information
            * Exploit Weak File Permissions
        * Modify Configuration to Redirect Traffic or Change Behavior
            * Change MQTT Broker Details to Point to Attacker's Broker
            * Modify Device Mappings to Control Different Devices
    * Intercept and Manipulate Communication Between Bridge and SmartThings API [CRITICAL NODE]
        * Man-in-the-Middle (MITM) Attack
            * Intercept Communication
                * ARP Spoofing on Local Network
                * DNS Spoofing
            * Modify API Requests
                * Send Unauthorized Commands to SmartThings Hub
                * Modify Device State Information
        * Replay Attacks
            * Capture Valid API Requests
            * Re-send Captured Requests to Trigger Actions
    * Exploit Insecure Storage of SmartThings API Credentials [CRITICAL NODE]
        * Access Stored Credentials
            * Exploit Weak File Permissions
        * Use Stolen Credentials to Directly Access SmartThings API
            * Control Devices Directly via SmartThings API
            * Access Device Data
```


## Attack Tree Path: [Gain Unauthorized Control of SmartThings Devices via Compromised Bridge](./attack_tree_paths/gain_unauthorized_control_of_smartthings_devices_via_compromised_bridge.md)

This represents the attacker's ultimate goal. Success in any of the high-risk paths or through the exploitation of other critical nodes leads to achieving this objective.

## Attack Tree Path: [Compromise MQTT Broker](./attack_tree_paths/compromise_mqtt_broker.md)

* **Gain Unauthorized Access to MQTT Broker:**
    * **Exploit Weak/Default Credentials:**
        * **Guess Common Passwords:** Attackers attempt to log in to the MQTT broker using commonly used usernames and passwords. This is a low-effort attack requiring minimal skill.
        * **Brute-force Credentials:** Attackers use automated tools to try a large number of username and password combinations to gain access. This requires slightly more effort and can be detected through monitoring login attempts.
* **Inject Malicious MQTT Messages:**
    * **Publish Crafted Control Messages:**
        * **Reverse Engineer Topic Structure:** Attackers analyze the MQTT traffic to understand the topic structure used by the bridge for controlling devices. This requires some technical skill and observation.
        * **Inject Commands to Control Devices Directly:** Once the topic structure is understood, attackers can publish MQTT messages that mimic legitimate control commands, directly manipulating SmartThings devices.

## Attack Tree Path: [Exploit Insecure Configuration](./attack_tree_paths/exploit_insecure_configuration.md)

* **Access Configuration Files with Sensitive Information:**
    * **Exploit Weak File Permissions:** Attackers exploit misconfigured file permissions on the server where the bridge is running to gain access to configuration files containing sensitive information like MQTT broker credentials or SmartThings API keys. This is a low-effort attack requiring basic knowledge of file systems.
* **Modify Configuration to Redirect Traffic or Change Behavior:**
    * **Change MQTT Broker Details to Point to Attacker's Broker:** Attackers modify the bridge's configuration to point it to a malicious MQTT broker under their control, allowing them to intercept and manipulate communication.
    * **Modify Device Mappings to Control Different Devices:** Attackers alter the configuration to associate different SmartThings devices with the bridge's control mechanisms, allowing them to control unintended devices.

## Attack Tree Path: [Intercept and Manipulate Communication Between Bridge and SmartThings API](./attack_tree_paths/intercept_and_manipulate_communication_between_bridge_and_smartthings_api.md)

* **Man-in-the-Middle (MITM) Attack:**
    * **Intercept Communication:**
        * **ARP Spoofing on Local Network:** Attackers on the same local network as the bridge manipulate ARP tables to redirect network traffic through their machine, allowing them to intercept communication between the bridge and the SmartThings API. This requires some network knowledge and readily available tools.
        * **DNS Spoofing:** Attackers manipulate DNS responses to redirect the bridge's requests to a malicious server, allowing them to intercept communication. This is more complex to execute reliably.
    * **Modify API Requests:**
        * **Send Unauthorized Commands to SmartThings Hub:** After intercepting the communication, attackers modify API requests sent by the bridge to the SmartThings hub to send unauthorized commands to control devices.
        * **Modify Device State Information:** Attackers alter API requests to change the reported state of SmartThings devices, potentially disrupting automation or misleading users.
* **Replay Attacks:**
    * **Capture Valid API Requests:** Attackers capture legitimate API requests sent by the bridge to the SmartThings API, often through network sniffing.
    * **Re-send Captured Requests to Trigger Actions:** Attackers re-send the captured API requests to the SmartThings API, potentially triggering actions on devices without proper authorization, especially if the API lacks replay protection.

## Attack Tree Path: [Exploit Insecure Storage of SmartThings API Credentials](./attack_tree_paths/exploit_insecure_storage_of_smartthings_api_credentials.md)

* **Access Stored Credentials:**
    * **Exploit Weak File Permissions:** Similar to exploiting insecure configuration files, attackers exploit weak file permissions on the server where the bridge is running to access files containing the SmartThings API credentials.
* **Use Stolen Credentials to Directly Access SmartThings API:**
    * **Control Devices Directly via SmartThings API:** With the stolen API credentials, attackers can bypass the bridge entirely and directly interact with the SmartThings API to control devices. This requires understanding the SmartThings API.
    * **Access Device Data:** Attackers can use the stolen credentials to directly access sensitive data from SmartThings devices through the API.

