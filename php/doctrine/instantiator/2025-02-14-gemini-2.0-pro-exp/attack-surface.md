# Attack Surface Analysis for doctrine/instantiator

## Attack Surface: [1. Unintended Class Instantiation](./attack_surfaces/1__unintended_class_instantiation.md)

    *   **Description:** An attacker manipulates the class name provided to the Instantiator, causing the application to create an object of an attacker-controlled class. This bypasses the intended constructor and any security checks it might contain.
    *   **How Instantiator Contributes:** The Instantiator's core function is to create objects *without* calling the constructor, making this attack possible. It directly facilitates the bypass of constructor-based security.
    *   **Example:**
        *   Application code: `$object = $instantiator->instantiate($_GET['class_name']);`
        *   Attacker provides: `?class_name=My\Evil\Class` (where `My\Evil\Class` has a `__wakeup` method that executes malicious code).
    *   **Impact:**
        *   Remote Code Execution (RCE)
        *   Denial of Service (DoS)
        *   Information Disclosure
        *   Privilege Escalation
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Whitelisting:** Maintain a hardcoded list of *only* the allowed class names.  Do *not* derive the class name from user input, even indirectly.  Use a configuration file or a mapping (e.g., a PHP array) to define the allowed classes.
        *   **Factory Pattern with Validation:** Use a factory method that takes a validated identifier (e.g., an enum or a key from a configuration array) and maps it to the corresponding class name *before* using the Instantiator.  The factory method can then perform additional post-instantiation setup and validation.
        *   **Avoid User Input:** Never directly use user-supplied data to determine the class name to be instantiated.

## Attack Surface: [2. Constructor Security Bypass](./attack_surfaces/2__constructor_security_bypass.md)

    *   **Description:** The Instantiator bypasses the constructor of the target class. Constructors often contain essential security logic, such as access control checks, input validation, and initialization of security-related properties.
    *   **How Instantiator Contributes:** This is the fundamental mechanism of the Instantiator – to avoid calling the constructor. This bypass is the *intended* behavior, but it's also the source of the risk.
    *   **Example:**
        ```php
        class User {
            private $isAdmin;

            public function __construct($username, $password) {
                // Authentication and authorization logic here
                if ($this->authenticate($username, $password)) {
                    $this->isAdmin = $this->checkAdminStatus($username);
                } else {
                    $this->isAdmin = false;
                }
            }
            // ... other methods ...
        }

        // Using Instantiator:
        $user = $instantiator->instantiate(User::class);
        // $user->isAdmin is now uninitialized (or has a default value, if any),
        // bypassing the authentication and authorization logic.
        ```
    *   **Impact:**
        *   Privilege Escalation (if the constructor enforces access control)
        *   Data Corruption (if the constructor validates input)
        *   Security Bypass (general weakening of security posture)
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Post-Instantiation Initialization:** Create a separate initialization method (e.g., `initialize()`, `setup()`, `validate()`) that performs the essential security checks and setup that would normally be in the constructor.  Call this method *immediately* after using the Instantiator.
        *   **Factory Pattern:** Encapsulate the Instantiator usage within a factory method.  The factory method instantiates the object, then calls the initialization method, ensuring that the object is always in a secure and consistent state.
        *   **Object State Validation:** Implement a method (e.g., `isValid()`) that checks the internal state of the object to ensure that all security-critical properties are properly initialized and that the object is in a valid state. Call this method before using the object.

