# Attack Surface Analysis for humanizr/humanizer

## Attack Surface: [Reliance on Formatted Output for Security Decisions](./attack_surfaces/reliance_on_formatted_output_for_security_decisions.md)

**Description:** The application makes security-sensitive decisions based on the *formatted* output of `humanizer`.

**How Humanizer Contributes:** `humanizer`'s primary function is for display purposes. Its output is not intended for programmatic parsing or security logic. Variations in formatting could lead to incorrect security decisions.

**Example:**  Parsing the human-readable file size to determine if a user has enough storage quota, instead of using the actual byte count. Different formatting could lead to misinterpretations, allowing a user to bypass quota limits.

**Impact:** Circumvention of security controls, unauthorized access or actions.

**Risk Severity:** High

**Mitigation Strategies:**
* **Avoid Parsing Formatted Output:** Never rely on the formatted output of `humanizer` for security-critical logic.
* **Use Raw Data:**  Base security decisions on the original, unformatted data (e.g., the raw byte count of a file, the actual timestamp).

