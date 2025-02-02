# Attack Surface Analysis for thoughtbot/factory_bot

## Attack Surface: [Code Injection via Factory Definitions/Callbacks](./attack_surfaces/code_injection_via_factory_definitionscallbacks.md)

**Description:** `factory_bot` executes Ruby code within factory definitions and callbacks. If these definitions are dynamically generated or influenced by untrusted input (highly improbable in typical usage, but theoretically possible in complex setups), it could lead to arbitrary code execution within the test environment *through factory_bot*.

**Factory Bot Contribution:** `factory_bot` is the execution engine for the Ruby code defined in factories and callbacks. Compromised definitions leverage `factory_bot` to execute malicious code.

**Example:**  (Highly contrived and insecure example) Imagine a factory definition dynamically constructed from an external, untrusted source:

```ruby
# Insecure and unrealistic example!
untrusted_code_snippet = "... some external input ..."
FactoryBot.define do
  factory :vulnerable_factory do
    # ... other attributes ...
    eval(untrusted_code_snippet) # factory_bot executes injected code!
  end
end
```
If `untrusted_code_snippet` contains malicious Ruby code, `factory_bot` will execute it when the `vulnerable_factory` is used in tests.

**Impact:**  **High to Critical**. Code execution within the test environment can lead to:
*   Data breaches in the test database (potentially containing sensitive data).
*   Compromise of development machines if the test environment is not properly isolated.
*   Supply chain attacks if malicious code is injected into shared factory definitions.

**Risk Severity:** **High** (Low probability in typical secure development, but **Critical** potential impact if exploited in misconfigured or compromised environments).

**Mitigation Strategies:**
*   **Treat factory definitions and callbacks as highly sensitive code.** Apply rigorous code review and secure coding practices.
*   **Absolutely avoid dynamic generation of factory definitions or callbacks based on external, untrusted input.** Factory definitions should be statically defined and strictly controlled by the development team.
*   **Implement robust input validation and sanitization** if any external data *must* influence test setup (though this should be avoided for factory definitions themselves).

## Attack Surface: [Bypass of Application Security Measures in Tests via Factory Design](./attack_surfaces/bypass_of_application_security_measures_in_tests_via_factory_design.md)

**Description:**  `factory_bot` factories, if not carefully designed, can create data that circumvents application-level validations and security constraints. This can lead to tests passing incorrectly, masking critical security vulnerabilities in the application that would be exposed with real-world data. *Factory_bot*, by design, allows direct database manipulation, bypassing application logic if factories are not aligned with application security rules.

**Factory Bot Contribution:** `factory_bot`'s direct database interaction capability allows creation of records that might not adhere to application security logic if factories are not meticulously designed to mirror application constraints.

**Example:** An application enforces strong password policies and email validation. A poorly designed factory might be:

```ruby
FactoryBot.define do
  factory :insecure_user do
    email "invalid-email" # factory_bot creates record bypassing email validation
    password "weak"      # factory_bot creates record bypassing password strength policy
    password_confirmation "weak"
  end
end
```
Tests using `insecure_user` factory might pass, even if the application correctly rejects invalid emails and weak passwords during user registration. This *factory_bot* usage masks critical validation vulnerabilities.

**Impact:** **High**.  False sense of security from passing tests. Critical vulnerabilities related to data validation, authorization, or other security mechanisms can be missed during testing and deployed to production, leading to real-world exploits.

**Risk Severity:** **High** (High probability if factories are not designed with security in mind, **Critical** impact due to potential for masking significant security flaws in production).

**Mitigation Strategies:**
*   **Design factories to strictly adhere to application-level validations and security constraints.** Factories should generate data that is valid and secure according to the application's security policies, mimicking real user input and respecting application logic.
*   **Explicitly test application validations and security constraints *separately* from factory usage.** Do not rely on factories to implicitly validate security. Create dedicated tests that specifically verify validation rules and security mechanisms are enforced correctly by the application, even when factories are used.
*   **Regularly audit and review factory definitions** to ensure they remain aligned with current application security requirements and data model.  Factories should be updated whenever application security policies change.

