# Attack Tree Analysis for marcuswestin/webviewjavascriptbridge

Objective: To compromise the application by executing arbitrary native code or accessing sensitive native data through vulnerabilities in the WebViewJavascriptBridge.

## Attack Tree Visualization

```
* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Insecure Message Handling **CRITICAL NODE**
        * Manipulate Message Content **HIGH-RISK PATH**
            * Craft Malicious JSON Payload **HIGH-RISK PATH**
                * Trigger Unintended Native Function Calls **HIGH-RISK PATH**
                    * Gain Access to Sensitive Native Data **HIGH-RISK PATH - CRITICAL NODE**
                    * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**
            * Inject Malicious JavaScript Code within Message
                * Native Code Executes Injected Script (if not properly sanitized) **HIGH-RISK PATH**
                    * Gain Access to Sensitive Native Data **HIGH-RISK PATH - CRITICAL NODE**
                    * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**
        * Spoof Message Origin **HIGH-RISK PATH**
            * Send Messages from Malicious Web Content **HIGH-RISK PATH**
                * Bypass Intended Access Controls **HIGH-RISK PATH**
                    * Trigger Unintended Native Function Calls **HIGH-RISK PATH**
                        * Gain Access to Sensitive Native Data **HIGH-RISK PATH - CRITICAL NODE**
                        * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**
    * Exploit Insecure Callback Mechanism **CRITICAL NODE**
        * Inject Malicious Callback Handler **HIGH-RISK PATH**
            * Register a Callback that Executes Malicious Code **HIGH-RISK PATH**
                * Native Code Executes Malicious Callback **HIGH-RISK PATH**
                    * Gain Access to Sensitive Native Data **HIGH-RISK PATH - CRITICAL NODE**
                    * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**
    * Exploit Lack of Input Validation/Sanitization **CRITICAL NODE**
        * Send Malicious Data Through Bridge **HIGH-RISK PATH**
            * Native Code Processes Unsanitized Input **HIGH-RISK PATH**
                * Buffer Overflow in Native Code **HIGH-RISK PATH**
                    * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**
                * Command Injection in Native Code **HIGH-RISK PATH**
                    * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**
                * Path Traversal in Native Code
                    * Access Sensitive Files **HIGH-RISK PATH - CRITICAL NODE**
```


## Attack Tree Path: [Gain Access to Sensitive Native Data](./attack_tree_paths/gain_access_to_sensitive_native_data.md)

* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Insecure Message Handling **CRITICAL NODE**
        * Manipulate Message Content **HIGH-RISK PATH**
            * Craft Malicious JSON Payload **HIGH-RISK PATH**
                * Trigger Unintended Native Function Calls **HIGH-RISK PATH**
                    * Gain Access to Sensitive Native Data **HIGH-RISK PATH - CRITICAL NODE**

## Attack Tree Path: [Execute Arbitrary Native Code](./attack_tree_paths/execute_arbitrary_native_code.md)

* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Insecure Message Handling **CRITICAL NODE**
        * Manipulate Message Content **HIGH-RISK PATH**
            * Craft Malicious JSON Payload **HIGH-RISK PATH**
                * Trigger Unintended Native Function Calls **HIGH-RISK PATH**
                    * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**

## Attack Tree Path: [Gain Access to Sensitive Native Data](./attack_tree_paths/gain_access_to_sensitive_native_data.md)

* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Insecure Message Handling **CRITICAL NODE**
        * Manipulate Message Content **HIGH-RISK PATH**
            * Inject Malicious JavaScript Code within Message
                * Native Code Executes Injected Script (if not properly sanitized) **HIGH-RISK PATH**
                    * Gain Access to Sensitive Native Data **HIGH-RISK PATH - CRITICAL NODE**

## Attack Tree Path: [Execute Arbitrary Native Code](./attack_tree_paths/execute_arbitrary_native_code.md)

* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Insecure Message Handling **CRITICAL NODE**
        * Manipulate Message Content **HIGH-RISK PATH**
            * Inject Malicious JavaScript Code within Message
                * Native Code Executes Injected Script (if not properly sanitized) **HIGH-RISK PATH**
                    * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**

## Attack Tree Path: [Gain Access to Sensitive Native Data](./attack_tree_paths/gain_access_to_sensitive_native_data.md)

* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Insecure Message Handling **CRITICAL NODE**
        * Spoof Message Origin **HIGH-RISK PATH**
            * Send Messages from Malicious Web Content **HIGH-RISK PATH**
                * Bypass Intended Access Controls **HIGH-RISK PATH**
                    * Trigger Unintended Native Function Calls **HIGH-RISK PATH**
                        * Gain Access to Sensitive Native Data **HIGH-RISK PATH - CRITICAL NODE**

## Attack Tree Path: [Execute Arbitrary Native Code](./attack_tree_paths/execute_arbitrary_native_code.md)

* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Insecure Message Handling **CRITICAL NODE**
        * Spoof Message Origin **HIGH-RISK PATH**
            * Send Messages from Malicious Web Content **HIGH-RISK PATH**
                * Bypass Intended Access Controls **HIGH-RISK PATH**
                    * Trigger Unintended Native Function Calls **HIGH-RISK PATH**
                        * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**

## Attack Tree Path: [Gain Access to Sensitive Native Data](./attack_tree_paths/gain_access_to_sensitive_native_data.md)

* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Insecure Callback Mechanism **CRITICAL NODE**
        * Inject Malicious Callback Handler **HIGH-RISK PATH**
            * Register a Callback that Executes Malicious Code **HIGH-RISK PATH**
                * Native Code Executes Malicious Callback **HIGH-RISK PATH**
                    * Gain Access to Sensitive Native Data **HIGH-RISK PATH - CRITICAL NODE**

## Attack Tree Path: [Execute Arbitrary Native Code](./attack_tree_paths/execute_arbitrary_native_code.md)

* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Insecure Callback Mechanism **CRITICAL NODE**
        * Inject Malicious Callback Handler **HIGH-RISK PATH**
            * Register a Callback that Executes Malicious Code **HIGH-RISK PATH**
                * Native Code Executes Malicious Callback **HIGH-RISK PATH**
                    * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**

## Attack Tree Path: [Execute Arbitrary Native Code](./attack_tree_paths/execute_arbitrary_native_code.md)

* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Lack of Input Validation/Sanitization **CRITICAL NODE**
        * Send Malicious Data Through Bridge **HIGH-RISK PATH**
            * Native Code Processes Unsanitized Input **HIGH-RISK PATH**
                * Buffer Overflow in Native Code **HIGH-RISK PATH**
                    * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**

## Attack Tree Path: [Execute Arbitrary Native Code](./attack_tree_paths/execute_arbitrary_native_code.md)

* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Lack of Input Validation/Sanitization **CRITICAL NODE**
        * Send Malicious Data Through Bridge **HIGH-RISK PATH**
            * Native Code Processes Unsanitized Input **HIGH-RISK PATH**
                * Command Injection in Native Code **HIGH-RISK PATH**
                    * Execute Arbitrary Native Code **HIGH-RISK PATH - CRITICAL NODE**

## Attack Tree Path: [Access Sensitive Files](./attack_tree_paths/access_sensitive_files.md)

* Compromise Application via WebViewJavascriptBridge **CRITICAL NODE**
    * Exploit Lack of Input Validation/Sanitization **CRITICAL NODE**
        * Send Malicious Data Through Bridge **HIGH-RISK PATH**
            * Native Code Processes Unsanitized Input **HIGH-RISK PATH**
                * Path Traversal in Native Code
                    * Access Sensitive Files **HIGH-RISK PATH - CRITICAL NODE**

