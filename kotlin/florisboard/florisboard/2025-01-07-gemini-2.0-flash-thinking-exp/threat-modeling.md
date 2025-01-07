# Threat Model Analysis for florisboard/florisboard

## Threat: [Supply Chain Compromise](./threats/supply_chain_compromise.md)

**Description:** An attacker compromises the FlorisBoard repository (e.g., via compromised maintainer accounts, vulnerabilities in the build process) and injects malicious code into the keyboard's codebase or release artifacts. This malicious code could be anything from a keylogger to a mechanism for remotely controlling devices.

**Impact:** Users of the application integrating the compromised FlorisBoard would unknowingly install and use a malicious keyboard. This could lead to the theft of all text entered through the keyboard (including passwords, personal information, and sensitive data), unauthorized access to device resources, or the execution of arbitrary code on the user's device.

**Affected Component:** The entire FlorisBoard codebase, build system, and release artifacts.

**Risk Severity:** Critical

## Threat: [Malicious Code Contribution](./threats/malicious_code_contribution.md)

**Description:** A malicious actor contributes seemingly benign code to the FlorisBoard project that, upon closer inspection or through later modifications, reveals malicious functionality. This could be done subtly to bypass initial code reviews.

**Impact:** Similar to supply chain compromise, but potentially affecting a smaller subset of users depending on when the malicious code was introduced and detected. Data theft, unauthorized access, and arbitrary code execution are possible.

**Affected Component:** Specific modules or features within the FlorisBoard codebase where the malicious code is injected.

**Risk Severity:** High

## Threat: [Data Logging by FlorisBoard](./threats/data_logging_by_florisboard.md)

**Description:** FlorisBoard, either intentionally (if compromised) or due to a vulnerability, logs keystrokes or other user input locally on the device or transmits this data to an external server controlled by an attacker.

**Impact:** Exposure of sensitive user data, including passwords, credit card details, personal messages, and other confidential information entered through the keyboard. This data could be used for identity theft, financial fraud, or other malicious purposes.

**Affected Component:** Input handling modules, data storage mechanisms (local files, databases), and network communication modules within FlorisBoard.

**Risk Severity:** High

## Threat: [Accessibility Service Abuse](./threats/accessibility_service_abuse.md)

**Description:** If FlorisBoard utilizes accessibility services (which allow it to observe and interact with screen content), vulnerabilities or malicious code could abuse these services to perform actions on behalf of the user without their explicit consent, potentially within the application or other parts of the device.

**Impact:** Unauthorized actions within the application (e.g., sending messages, making purchases), data theft by observing screen content, or other malicious activities performed silently in the background.

**Affected Component:** Accessibility service implementation within FlorisBoard.

**Risk Severity:** High

