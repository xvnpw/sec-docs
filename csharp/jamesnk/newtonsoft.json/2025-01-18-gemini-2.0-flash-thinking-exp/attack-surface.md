# Attack Surface Analysis for jamesnk/newtonsoft.json

## Attack Surface: [Insecure Deserialization via `TypeNameHandling`](./attack_surfaces/insecure_deserialization_via__typenamehandling_.md)

**Description:**  Allows embedding type information within the JSON payload, enabling the instantiation of arbitrary types during deserialization.

**How Newtonsoft.Json Contributes:** The `TypeNameHandling` setting in `JsonSerializerSettings` directly controls this behavior. When set to values like `All` or `Auto`, it instructs the library to use the type information present in the JSON.

**Example:** An attacker sends a JSON payload like `{"$type": "System.Windows.Forms.AxHost.State, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089", "control": {"Assembly": "System.Diagnostics.Process", "ClassName": "System.Diagnostics.Process", "CreateInstance": true, "StartInfo": {"FileName": "calc.exe"}}}`. When deserialized with vulnerable `TypeNameHandling`, it can execute `calc.exe`.

**Impact:** Remote Code Execution (RCE), allowing attackers to execute arbitrary code on the server or client.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   Avoid using `TypeNameHandling.All` or `TypeNameHandling.Auto`.

