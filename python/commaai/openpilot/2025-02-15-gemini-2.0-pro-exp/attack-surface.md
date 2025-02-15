# Attack Surface Analysis for commaai/openpilot

## Attack Surface: [CAN Bus Injection (via openpilot)](./attack_surfaces/can_bus_injection__via_openpilot_.md)

*   **Description:**  Unauthorized modification of messages on the vehicle's CAN bus *through the compromised openpilot device*.
*   **openpilot Contribution:** openpilot's *required* CAN bus access for core functionality creates the direct pathway. It acts as a potentially compromised bridge.
*   **Example:** An attacker, having gained RCE on the openpilot device, sends CAN messages to disable the brakes.
*   **Impact:** Loss of vehicle control, unintended actions (acceleration, braking, steering), disabling safety systems, vehicle damage, injury/death.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Secure Boot:** Prevent unauthorized firmware execution.
        *   **Strict CAN Message Filtering:**  Implement rigorous input validation and filtering (both inbound and outbound) on the CAN bus.  Whitelist allowed messages; blacklist/reject all others.
        *   **CAN Bus Intrusion Detection (IDS):** Monitor for anomalous CAN traffic patterns.
        *   **Hardware Security Module (HSM):**  Protect cryptographic keys and enable secure CAN message signing/verification.
        *   **Code Hardening (CAN Interface):** Focus secure coding practices specifically on the CAN communication code.
    *   **Users:**
        *   **Physical Device Security:** Prevent unauthorized physical access to the openpilot hardware.

## Attack Surface: [Remote Code Execution (RCE) on openpilot Device](./attack_surfaces/remote_code_execution__rce__on_openpilot_device.md)

*   **Description:**  An attacker gains the ability to execute arbitrary code on the openpilot device itself.
*   **openpilot Contribution:** openpilot's software complexity, reliance on external libraries (C++, Python, OS components), and network connectivity (Wi-Fi, cloud) create the vulnerability surface.
*   **Example:** Exploiting a buffer overflow in openpilot's image processing code via a crafted image sent over Wi-Fi.
*   **Impact:**  Complete device compromise, leading to CAN bus injection (see above), data exfiltration, and potential lateral movement within the vehicle's network.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Secure Coding Practices (OWASP):**  Adhere rigorously to secure coding guidelines.
        *   **Memory Safety:** Prioritize memory-safe languages (e.g., Rust) or robust memory management in C/C++.
        *   **Regular Vulnerability Scanning:** Employ static and dynamic analysis tools.
        *   **Dependency Management (SBOM):**  Track, vet, and update all dependencies.
        *   **Sandboxing:** Isolate openpilot components (sensor processing, control, networking) to contain breaches.
        *   **Secure Update Mechanism:**  Implement robust, cryptographically verified updates.
        *   **Principle of Least Privilege:** Minimize privileges for openpilot processes.
    *   **Users:**
        *   **Prompt Software Updates:** Install updates immediately when available.
        *   **Strong Wi-Fi Security:** Use a strong, unique password for the connected Wi-Fi network.

## Attack Surface: [Sensor Spoofing Leading to Incorrect Model Decisions (openpilot-Specific)](./attack_surfaces/sensor_spoofing_leading_to_incorrect_model_decisions__openpilot-specific_.md)

*   **Description:**  Manipulating sensor data (camera, radar) to cause openpilot's *specific* machine learning models and control algorithms to make incorrect driving decisions.
*   **openpilot Contribution:**  This is *not* general sensor spoofing; it's about exploiting the *unique* way openpilot processes and reacts to sensor data. The vulnerability lies in openpilot's specific model architecture, training data, and sensor fusion logic.
*   **Example:**  Projecting a fake lane marking that *specifically* triggers a misclassification in openpilot's lane detection model, causing a lane departure.
*   **Impact:**  Incorrect lane keeping, false obstacle detection/avoidance, incorrect speed control, leading to potential accidents.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Sensor Fusion with Redundancy:** Cross-validate data from multiple, independent sensors.
        *   **Adversarial Training:** Train models with adversarial examples to improve robustness.
        *   **Anomaly Detection (Sensor Data):**  Detect physically impossible or highly improbable sensor readings.
        *   **Contextual Awareness:** Integrate map data, time of day, and other contextual information to validate sensor input.
        *   **Out-of-Distribution (OOD) Detection:** Identify when sensor inputs deviate significantly from training data.
    *   **Users:**
        *   **Maintain Sensor Cleanliness:** Ensure sensors are unobstructed.
        *   **Situational Awareness:** Remain attentive and ready to take over control.

## Attack Surface: [Model Poisoning / Data Poisoning (Targeting openpilot's Models)](./attack_surfaces/model_poisoning__data_poisoning__targeting_openpilot's_models_.md)

*   **Description:**  Tampering with the training data used to create openpilot's machine learning models, causing them to misbehave in specific, attacker-controlled ways. This targets the *specific* models used by openpilot.
*   **openpilot Contribution:** The vulnerability exists because openpilot relies on machine learning and updates to those models. The attack targets the integrity of *openpilot's* training pipeline.
*   **Example:**  Subtly modifying a dataset of driving images to cause openpilot's lane-keeping model to consistently drift left under specific, rare conditions.
*   **Impact:**  Subtle but potentially dangerous misbehavior of openpilot, difficult to detect until triggered, leading to accidents in specific scenarios.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Data Provenance and Integrity:**  Securely track and verify the origin and integrity of all training data.
        *   **Data Sanitization:**  Thoroughly inspect and clean training data.
        *   **Robust Training Techniques:**  Employ methods less susceptible to data poisoning (adversarial training, differential privacy).
        *   **Model Monitoring:**  Continuously monitor deployed model performance for anomalies.
        *   **Red Team Exercises (Data Poisoning):** Simulate poisoning attacks to test defenses.
        *   **Secure Model Storage:** Protect trained models from unauthorized access.
    *   **Users:** (Limited direct mitigation; relies on developer actions)
        *   **Install Only Official Updates:** Ensure updates come directly from comma.ai and are verified.

