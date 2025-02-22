- **Vulnerability Name:** Stored Cross‑Site Scripting (XSS) via Audit Log Entries
  - **Description:**
    An attacker who can supply malicious data into a model’s fields—for example via a public form or other externally provided input—may inject an HTML/JavaScript payload (such as `<script>alert("xss")</script>`) into a field. When the model’s string representation (for example provided by a custom `__str__` method) is captured by the audit logging system, the unsanitized value may later be rendered in an administrator’s audit log view. In our review, we observed that audit log entries (and difference information produced by the function `model_instance_diff` in `diff.py`) are built by calling helper functions like `get_field_value` that simply convert field values to strings (using Django’s `smart_str`) without applying an additional layer of HTML escaping. If the log viewing template or admin view does not apply uniform escaping, then an injected payload will be executed in the administrator’s browser.
  - **Impact:**
    Successful exploitation may allow an attacker to perform arbitrary JavaScript execution in an administrator’s browser. This can lead to session hijacking, extraction of sensitive session cookies, exfiltration of confidential audit trails, or further compromise of administrative functions.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    - Many output routines in the admin mixins (for example, those using Django’s `format_html` and related safe string helpers) escape values by default.
    - Log entry values are serialized and formatted via Django’s formatting functions (see methods such as `changes_display_dict`) before being displayed.
  - **Missing Mitigations:**
    - There is no explicit and “defense in depth” sanitization when incorporating data from untrusted model fields into audit log entries or diff reports.
    - The audit log code defers the responsibility for producing safe textual representations (via model methods such as `__str__`) to the calling application, with no blanket mechanism to re‑escape all logged content immediately prior to rendering.
  - **Preconditions:**
    - The application must allow external (or public) submission of data that is subsequently tracked by audit logging (e.g. via a web form or API).
    - An administrator (or similarly privileged user) must later access an audit log view where the unsanitized content is rendered (for example, in the Django admin interface).
  - **Source Code Analysis:**
    - In the file `diff.py`, the function `get_field_value` converts field values to strings using `smart_str` without additional sanitization. For DateTime and JSONField types the routines perform conversion (and a call to `json.dumps` for JSONField) but do not perform HTML escaping.
    - The function `model_instance_diff` iterates over model fields (selected via `_meta.get_fields()` and filtered by the helper `track_field`) and uses the possibly malicious output of `get_field_value` to build a diff dict without extra sanitization.
    - Earlier in the audit logging process (for example, via the call to Python built‑in `str(instance)` when capturing an object’s representation), an attacker‑controlled string (for example returned by a malicious `__str__` method) may already be embedded in log entries.
    - These issues combined mean that if unsanitized data is stored in audit logs it may later be rendered without sufficient protection even if some parts of the output use Django safe string helpers.
  - **Security Test Case:**
    1. Identify or create a model that is tracked by the audit logging system.
    2. Modify (or simulate) the model so that a field (or the model’s `__str__` method) returns a malicious payload such as `<script>alert("xss")</script>`.
    3. Submit this data (for example, via a public form) so that a new or updated instance is saved and captured by auditlog along with its diff data.
    4. Log in as an administrator and navigate to the audit log view where log entries and change audits are rendered.
    5. Verify that the malicious payload appears unsanitized in the output and, upon rendering in the browser, that the JavaScript code executes.

---

- **Vulnerability Name:** Sensitive Data Exposure via Serialized Audit Log Entries
  - **Description:**
    The audit logging system optionally records a JSON‑serialized snapshot of a model’s state in the `serialized_data` field. If a tracked model contains sensitive information (for instance PII, financial data, or credentials) and such fields are not designated for masking via the registry’s `mask_fields` option, then that sensitive data will be stored in cleartext in the audit log. Our review of the diff‑calculation logic in `diff.py` confirms that unless the field name is explicitly flagged for masking, its value is output directly. An attacker with access to the audit logs—via an exposed admin interface, misconfigured API endpoint, or similar vector—could retrieve and abuse this confidential information.
  - **Impact:**
    Exposure of sensitive or confidential information to an attacker can lead to identity theft, fraud, reputational harm, or provide the adversary with intelligence to carry out further targeted attacks.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    - The audit logging registry allows developers to supply a list of sensitive fields to be masked via the `mask_fields` parameter.
    - When computing field differences in `model_instance_diff` (in `diff.py`), if a field is configured to be masked then its old and new values are passed through a masking function (`mask_str`) prior to logging.
    - It is generally expected that access to audit logs (for example in the Django Admin) is protected by robust authentication and permission checks.
  - **Missing Mitigations:**
    - There is no enforced or automatic masking (or encryption at rest) for all potentially sensitive fields; it relies entirely on explicit configurations in `mask_fields`.
    - There is no secondary layer of automated sensitivity scanning to catch fields that might have been inadvertently omitted from the masking configuration.
  - **Preconditions:**
    - The application is configured to capture a serialized snapshot of model state (i.e. using `serialize_data=True` for one or more models).
    - A model being tracked by auditlog contains sensitive data in one or more fields that are not included in the registry’s `mask_fields` configuration.
    - An attacker can access audit log entries—for example, by exploiting misconfigured access controls on the log viewing interface.
  - **Source Code Analysis:**
    - In `diff.py`, inside the `model_instance_diff` function, after comparing old and new field values (obtained via `get_field_value`), the code checks whether the field name belongs to `mask_fields`. If it does, both the old and new values are passed through the `mask_str` function before being stored in the diff.
    - Fields that are not flagged in `mask_fields` are logged in cleartext via a call to `smart_str` without masking.
    - In the migration files (for example, in `0011_logentry_serialized_data.py`), the audit log model schema is defined to include the `serialized_data` JSONField. When using Django’s serialization routines (as seen in methods like `_get_serialized_data_or_none`), data is stored directly without any enforced encryption or masking.
  - **Security Test Case:**
    1. Select a model that is tracked by auditlog and that contains a field with sensitive data (for example, a “credit_card” or “ssn” field).
    2. Register the model with auditlog and deliberately leave the sensitive field out of the `mask_fields` configuration.
    3. Create or update an instance of the model with representative sensitive data.
    4. Verify that a corresponding audit log entry is created and inspect its `serialized_data` field (for example, through the Django Admin or via a direct database query).
    5. Confirm that the sensitive values appear in cleartext in the serialized JSON.
    6. (Optional) Reconfigure the registration to include the sensitive field in `mask_fields` and repeat the test to verify that the data is thereafter masked.