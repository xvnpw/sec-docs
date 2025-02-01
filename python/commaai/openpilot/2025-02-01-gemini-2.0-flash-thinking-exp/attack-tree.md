# Attack Tree Analysis for commaai/openpilot

Objective: Compromise Application Using Openpilot to Gain Unauthorized Access, Data Manipulation, or Disrupt Service.

## Attack Tree Visualization

**Compromise Application Using Openpilot (OR)**
├── **1. Exploit Openpilot Software Vulnerabilities (OR)**
│   ├── **1.1 Code Injection Vulnerabilities (OR)**
│   │   ├── 1.1.1 Python Code Injection (AND)
│   │   │   └── 1.1.1.2 Inject Malicious Python Code (e.g., via crafted configuration, exploiting insecure deserialization if applicable)
│   ├── **1.2 Logic Bugs and Design Flaws (OR)**
│   │   ├── 1.2.1 Path Planning Logic Exploitation (AND)
│   │   │   └── 1.2.1.2 Craft Scenarios to Cause Unexpected Path Planning Behavior (e.g., leading to dangerous maneuvers, system instability)
│   │   ├── 1.2.2 Control System Manipulation (AND)
│   │   │   └── 1.2.2.2 Inject Data or Conditions to Manipulate Vehicle Controls (e.g., via CAN bus injection, sensor spoofing - see section 2)
├── **2. Manipulate Openpilot Input Data (OR)**
│   ├── **2.1 Sensor Spoofing (OR)**
│   │   ├── 2.1.1 Camera Spoofing (AND)
│   │   │   └── 2.1.1.2 Inject Fake Camera Data (e.g., using video injection, adversarial patches on physical environment)
│   │   ├── 2.1.3 GPS Spoofing (AND)
│   │   │   └── 2.1.3.2 Inject Fake GPS Data (e.g., to alter location information)
│   │   ├── **2.1.4 CAN Bus Injection (AND)**
│   │   │   ├── 2.1.4.1 Gain Access to CAN Bus (e.g., via OBD-II port, physical access to vehicle network)
│   │   │   └── 2.1.4.2 Inject Malicious CAN Messages (e.g., to control vehicle functions, manipulate sensor data relayed via CAN)
│   │   └── 2.1.5 Environmental Manipulation (AND)
│   │       └── 2.1.5.1 Alter Physical Environment (e.g., using adversarial stickers, laser pointers to confuse sensors)
├── **3. Exploit Openpilot's External Interfaces (OR)**
│   ├── **3.1 Network Communication Exploitation (OR)**
│   │   ├── **3.1.1 WiFi Network Attacks (AND)**
│   │   │   ├── 3.1.1.1 Identify WiFi Networks Used by Openpilot Device (e.g., for internet access, remote management)
│   │   │   └── 3.1.1.2 Exploit WiFi Vulnerabilities (e.g., weak passwords, WPS attacks, vulnerabilities in WiFi stack) to gain network access
│   ├── **3.2 Physical Interface Exploitation (OR)**
│   │   ├── **3.2.1 USB Interface Exploitation (AND)**
│   │   │   ├── 3.2.1.1 Gain Physical Access to USB Ports on Openpilot Device (e.g., EON)
│   │   │   └── 3.2.1.2 Exploit USB Vulnerabilities (e.g., USB drive-by attacks, malicious USB devices, exploiting USB stack vulnerabilities)
├── **5. Physical Access and Device Tampering (OR)**
│   ├── **5.1 Device Theft (AND)**
│   │   ├── 5.1.1 Gain Physical Access to Openpilot Device (e.g., EON)
│   │   └── 5.1.2 Steal Device to Analyze and Extract Data/Secrets (e.g., access logs, configuration, cryptographic keys)
│   ├── 5.3 Data Extraction from Storage (AND)
│   │   ├── 5.3.1 Gain Physical Access to Openpilot Device
│   │   └── 5.3.2 Extract Data from Storage Media (e.g., SD card, internal storage) to access sensitive information (logs, user data, calibration data)

## Attack Tree Path: [1. Exploit Openpilot Software Vulnerabilities](./attack_tree_paths/1__exploit_openpilot_software_vulnerabilities.md)

* **Attack Vectors:**
    * **Code Injection Vulnerabilities:**
        * **Python Code Injection:**
            * **Inject Malicious Python Code:** Attackers can attempt to inject malicious Python code by exploiting input points to Python interpreters within Openpilot. This could be through:
                * Crafted configuration files that are parsed and executed.
                * User inputs that are not properly sanitized and are passed to Python modules.
                * Exploiting insecure deserialization vulnerabilities if Openpilot uses deserialization of untrusted data.
    * **Logic Bugs and Design Flaws:**
        * **Path Planning Logic Exploitation:**
            * **Craft Scenarios to Cause Unexpected Path Planning Behavior:** Attackers can analyze path planning algorithms and craft specific scenarios (e.g., adversarial examples, unusual road conditions) to trigger logic bugs. This can lead to:
                * Dangerous maneuvers by the vehicle.
                * System instability or crashes.
        * **Control System Manipulation:**
            * **Inject Data or Conditions to Manipulate Vehicle Controls:** Attackers can inject malicious data or conditions to manipulate the control system. This can be achieved through:
                * CAN bus injection (see section 2.1.4).
                * Sensor spoofing (see section 2.1).

## Attack Tree Path: [2. Manipulate Openpilot Input Data](./attack_tree_paths/2__manipulate_openpilot_input_data.md)

* **Attack Vectors:**
    * **Sensor Spoofing:**
        * **Camera Spoofing:**
            * **Inject Fake Camera Data:** Attackers can intercept and replace the camera input stream with fake data. Methods include:
                * Video injection by physically connecting to the camera input.
                * Adversarial patches placed in the physical environment to mislead the camera perception.
        * **GPS Spoofing:**
            * **Inject Fake GPS Data:** Attackers can use GPS spoofing devices to transmit fake GPS signals, altering the perceived location of the Openpilot system.
        * **CAN Bus Injection:**
            * **Gain Access to CAN Bus:** Attackers can gain access to the vehicle's CAN bus through:
                * The OBD-II port, which is often easily accessible.
                * Physical access to the vehicle's internal network.
            * **Inject Malicious CAN Messages:** Once on the CAN bus, attackers can inject malicious CAN messages to:
                * Control vehicle functions directly (steering, acceleration, braking).
                * Manipulate sensor data relayed over CAN, influencing Openpilot's perception.
        * **Environmental Manipulation:**
            * **Alter Physical Environment:** Attackers can subtly alter the physical environment to confuse Openpilot's sensors, such as:
                * Using adversarial stickers to mislead object detection algorithms.
                * Using laser pointers to disrupt camera or LiDAR sensors.

## Attack Tree Path: [3. Exploit Openpilot's External Interfaces](./attack_tree_paths/3__exploit_openpilot's_external_interfaces.md)

* **Attack Vectors:**
    * **Network Communication Exploitation:**
        * **WiFi Network Attacks:**
            * **Identify WiFi Networks Used by Openpilot Device:** Attackers can easily scan for and identify WiFi networks used by Openpilot devices.
            * **Exploit WiFi Vulnerabilities:** Attackers can exploit vulnerabilities in WiFi networks to gain access, including:
                * Weak passwords.
                * WPS attacks.
                * Vulnerabilities in the WiFi stack of the Openpilot device or access point.
    * **Physical Interface Exploitation:**
        * **USB Interface Exploitation:**
            * **Gain Physical Access to USB Ports on Openpilot Device:** USB ports on devices like EON are often physically accessible.
            * **Exploit USB Vulnerabilities:** Attackers can exploit USB vulnerabilities through:
                * USB drive-by attacks using malicious USB drives.
                * Malicious USB devices that emulate keyboards or network adapters.
                * Exploiting vulnerabilities in the USB stack of the Openpilot device.

## Attack Tree Path: [5. Physical Access and Device Tampering](./attack_tree_paths/5__physical_access_and_device_tampering.md)

* **Attack Vectors:**
    * **Device Theft:**
        * **Gain Physical Access to Openpilot Device:** Physical access to the Openpilot device (e.g., EON) is often possible depending on the deployment scenario.
        * **Steal Device to Analyze and Extract Data/Secrets:** Once stolen, attackers can:
            * Analyze the device's software and hardware in detail.
            * Extract sensitive data such as logs, configuration files, and cryptographic keys.
    * **Data Extraction from Storage:**
        * **Gain Physical Access to Openpilot Device:** Physical access is required.
        * **Extract Data from Storage Media:** Attackers can remove storage media (SD card, internal storage) and:
            * Directly access the data on another system.
            * Recover sensitive information like logs, user data, and calibration data if not properly encrypted.

