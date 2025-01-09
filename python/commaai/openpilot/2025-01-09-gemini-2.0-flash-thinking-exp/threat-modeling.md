# Threat Model Analysis for commaai/openpilot

## Threat: [Malicious CAN Bus Message Injection](./threats/malicious_can_bus_message_injection.md)

- **Description**: An attacker could inject crafted CAN (Controller Area Network) messages onto the vehicle's network via vulnerabilities in the system where Openpilot is running or through compromised components that interact with the CAN bus (and are controlled or influenced by Openpilot). This could involve sending commands to control actuators (steering, throttle, brakes) directly, potentially overriding Openpilot's intended actions or causing unintended behavior initiated by Openpilot.
- **Impact**: Critical. This could lead to loss of vehicle control, accidents, and physical harm to occupants and others due to actions directly influenced or initiated by malicious input affecting Openpilot's operation.
- **Affected Component**: CAN bus interface (specifically the interface used by `controlsd` within Openpilot to send commands and receive data).
- **Risk Severity**: Critical
- **Mitigation Strategies**:
  - Implement CAN bus message authentication and integrity checks within Openpilot's CAN communication logic.
  - Employ a secure CAN bus gateway that filters and validates messages before they reach the vehicle's critical systems and Openpilot.
  - Harden the system running Openpilot against intrusion to prevent attackers from directly injecting CAN messages.
  - Regularly update Openpilot and vehicle firmware to patch known vulnerabilities that could be exploited for CAN bus injection.

## Threat: [Spoofed GPS Signals](./threats/spoofed_gps_signals.md)

- **Description**: An attacker could use a GPS spoofing device to transmit false GPS signals, causing Openpilot's `locationd` module to receive incorrect location data. This could lead to Openpilot making incorrect driving decisions based on the false location, such as initiating lane changes or speed adjustments in the wrong areas, or completely disrupting its ability to localize the vehicle.
- **Impact**: High. Could lead to navigation errors and unsafe maneuvers directly caused by Openpilot's misinterpretation of its location, potentially resulting in accidents, especially in scenarios relying heavily on accurate location data for autonomous functions.
- **Affected Component**: `locationd` module within Openpilot (responsible for processing GPS data).
- **Risk Severity**: High
- **Mitigation Strategies**:
  - Implement multi-sensor fusion within `locationd` to verify GPS data with other sensor inputs (IMU, wheel speed, visual odometry) to detect inconsistencies.
  - Develop anomaly detection mechanisms within `locationd` to flag suspicious GPS signals based on velocity, direction, and sudden jumps.
  - Explore using secure and authenticated GPS sources if available and compatible with Openpilot.
  - Implement robust sanity checks and plausibility checks on received GPS coordinates within `locationd`.

## Threat: [Tampering with Openpilot Models](./threats/tampering_with_openpilot_models.md)

- **Description**: An attacker who gains unauthorized access to the system running Openpilot could modify the machine learning models used by Openpilot (e.g., for object detection, lane keeping). This could involve replacing models with malicious ones designed to misinterpret the environment or subtly altering existing models to introduce biases that cause Openpilot to make incorrect or unsafe driving decisions.
- **Impact**: High. Could lead to Openpilot misidentifying objects, failing to detect hazards, incorrectly tracking lanes, and making unsafe driving maneuvers directly resulting from the compromised models.
- **Affected Component**: Model loading and inference modules within various Openpilot daemons (e.g., `camerad` for vision models, `plannerd` for planning models).
- **Risk Severity**: High
- **Mitigation Strategies**:
  - Implement integrity checks and digital signatures for model files within Openpilot to ensure they haven't been tampered with.
  - Store model files in read-only locations with restricted access on the system running Openpilot.
  - Regularly audit and retrain models on clean and diverse datasets to detect and mitigate potential biases or vulnerabilities.
  - Employ model monitoring techniques within Openpilot to detect anomalies in model behavior and output during runtime.

## Threat: [Data Injection into Openpilot Processes](./threats/data_injection_into_openpilot_processes.md)

- **Description**: An attacker could exploit vulnerabilities in Openpilot's inter-process communication (IPC) mechanisms or memory management to inject malicious data into the internal data streams or memory of Openpilot processes. This could lead to Openpilot making decisions based on fabricated information, causing crashes, incorrect calculations, or unintended control actions.
- **Impact**: High. Could lead to system instability within Openpilot and potentially unsafe driving maneuvers directly caused by Openpilot processing and acting upon injected malicious data.
- **Affected Component**: Various Openpilot daemons and their inter-process communication mechanisms (e.g., using shared memory, sockets, messaging queues).
- **Risk Severity**: High
- **Mitigation Strategies**:
  - Implement robust input validation and sanitization for all data received through Openpilot's IPC mechanisms.
  - Employ memory-safe programming practices and languages where feasible within Openpilot's development.
  - Regularly audit Openpilot's code for memory corruption vulnerabilities (e.g., buffer overflows) and insecure IPC implementations.
  - Utilize secure inter-process communication mechanisms with authentication and authorization within Openpilot.

