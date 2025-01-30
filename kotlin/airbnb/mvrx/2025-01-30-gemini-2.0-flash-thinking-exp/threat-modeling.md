# Threat Model Analysis for airbnb/mvrx

## Threat: [Unintentional Exposure of Sensitive Data in State](./threats/unintentional_exposure_of_sensitive_data_in_state.md)

**Description:** An attacker might gain access to sensitive data (e.g., API keys, user credentials, PII) if developers inadvertently store this data directly in MvRx state objects. This data could be exposed through logs, debugging tools, or accidental persistence. An attacker could exploit this exposed data to gain unauthorized access to user accounts, backend systems, or sensitive information.
**Impact:** Data breach, privacy violation, unauthorized access to resources, reputational damage.
**MvRx Component Affected:** State objects (Data classes), `ViewModel.setState`, `ViewModel.withState`, Logging mechanisms (if state is logged).
**Risk Severity:** High
**Mitigation Strategies:**
*   Avoid storing sensitive data directly in state objects.
*   Encrypt or mask sensitive data if it must be part of the state.
*   Implement strict logging policies, especially in production, and sanitize state information before logging.
*   Use secure storage mechanisms like Android Keystore for sensitive credentials.
*   Regularly review state objects for sensitive data.

