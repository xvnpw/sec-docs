## Combined Vulnerability List

The following vulnerabilities have been identified in the django-modeltranslation project.

### Vulnerability 1: Arbitrary Module Import via Misconfigured Translation Files

**Description:**
The autodiscover routine in `modeltranslation/models.py` reads module names from the setting `MODELTRANSLATION_TRANSLATION_FILES` (exported as `TRANSLATION_FILES`) and directly passes each module name to Python’s `import_module()` without additional validation. In deployments where settings might be influenced—through misconfiguration, insecure configuration management, or template injection—a malicious module name could be injected. When the autodiscover routine runs, the attacker’s module is imported and its top‑level code is executed, potentially allowing remote code execution.

**Impact:**
Successful exploitation would allow an attacker to execute arbitrary Python code in the application context. This compromises application confidentiality and integrity and may enable lateral movement within the hosting environment.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The code relies on Django settings being defined only by trusted developers and assumes that settings (including `MODELTRANSLATION_TRANSLATION_FILES`) are not externally modifiable.
- No runtime validation or sanitization beyond Django’s standard settings enforcement is performed.

**Missing Mitigations:**
- Input validation and whitelisting of acceptable module names.
- A safe default or runtime check to prevent importing arbitrary module paths.

**Preconditions:**
- The attacker must be able to influence the application’s settings (for example, via misconfiguration or insecure configuration management).

**Source Code Analysis:**
- In `modeltranslation/models.py`, the `autodiscover()` function retrieves module names from the `TRANSLATION_FILES` setting.
- It iterates over the provided names and calls `import_module(module)` on each string without sanitization.
- If an attacker can inject a module name, its top‐level code will execute upon import.

**Security Test Case:**
1. In a controlled test environment, modify the Django settings file (or configuration management tool) to add `"malicious_module"` to `MODELTRANSLATION_TRANSLATION_FILES`.
2. Create a corresponding Python package named `malicious_module` that, when imported, performs an observable action (for example, writing a marker file or logging a distinctive message).
3. Restart the application to trigger the autodiscover routine.
4. Verify that the marker file exists or that the special log entry is present.

### Vulnerability 2: Potential Cross‑Site Scripting in Wrapped Widget Rendering

**Description:**
The `ClearableWidgetWrapper` in `modeltranslation/widgets.py` wraps a widget by rendering its HTML output and appending a “clear” checkbox. Although the implementation applies Django’s `conditional_escape()` to inserted values and marks the final HTML as safe, if a custom widget is used that returns pre-escaped (“safe”) HTML or bypasses proper escaping, an attacker’s injected malicious JavaScript might be rendered unescaped. This scenario can occur if translation fields or misconfigured custom widgets supply the input.

**Impact:**
Exploitation may allow an attacker to run arbitrary JavaScript in the browser of an administrator or user. The risk includes session hijacking, defacement, or additional client‑side attacks.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- In the `render()` method, each component (the wrapped widget’s HTML output, checkbox label, and element IDs) is passed through `conditional_escape()` before being combined and marked safe via `mark_safe()`.

**Missing Mitigations:**
- Additional context‑sensitive output encoding or policies ensuring that custom widgets never return pre-escaped HTML flagged as “safe.”
- Periodic review of custom widget implementations to ensure secure integration with `ClearableWidgetWrapper`.

**Preconditions:**
- An attacker must be able to supply or influence input—for instance, via a publicly accessible form field that uses the translation widget—or a custom widget is in place that bypasses proper escaping.

**Source Code Analysis:**
- The `ClearableWidgetWrapper.render()` method calls the wrapped widget’s `render()` to obtain HTML output.
- It then constructs a compound HTML snippet combining the widget output with a checkbox input.
- Although each piece is passed through `conditional_escape()`, if any part is already marked “safe” (such as from a misbehaving custom widget), untrusted data may be rendered directly.

**Security Test Case:**
1. In a test deployment exposing (for example) the Django admin, log in as an administrator.
2. Navigate to a form that uses a translation field rendered with the `ClearableWidgetWrapper`.
3. Inject a payload (for example, `"><script>alert('XSS');</script>`) into a translation field that is rendered using a custom widget which bypasses escaping.
4. Reload the form page and inspect the HTML; if the payload is not properly escaped and the JavaScript executes, the vulnerability is confirmed.

### Vulnerability 3: Unauthorized Data Exposure via Translation Fallback Mechanism

**Description:**
The translation field descriptor in `modeltranslation/fields.py` implements a fallback mechanism. When a translated value is requested, the code invokes `resolution_order(get_language(), self.fallback_languages)` to determine which localized field to return. If fallback settings are misconfigured or an attacker can force the active language (for example, via HTTP headers, cookies, or URL parameters), the application might return translation data from a locale that is not appropriate for the current user.

**Impact:**
Exploitation could cause pages to display translation content that includes sensitive or restricted information not intended for the active user, leading to unauthorized data disclosure and privacy breaches.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The fallback mechanism is solely driven by global application settings and the return value of `get_language()`, with no per‑user access controls or additional sanitization to prevent exposure of sensitive translation data.

**Missing Mitigations:**
- Implementation of access controls or filtering to ensure fallback translations are only used for content safe in the current user’s context.
- Additional checks to prevent fallback use of translations that may contain sensitive data when the active language is influenced by attacker‑controlled inputs.

**Preconditions:**
- The attacker must be able to influence the active language (for example, via the `Accept-Language` header, a cookie, or a URL parameter).
- The application’s configuration includes fallback translations that could contain sensitive information.

**Source Code Analysis:**
- In `TranslationFieldDescriptor.__get__()`, the method calls `resolution_order(get_language(), self.fallback_languages)` to establish a priority list of language codes.
- It then iterates over this list to return the first “meaningful” (i.e. non‑empty) translation.
- Because there is no mechanism preventing the attacker‑controlled language from being treated as primary, unauthorized fallback translations may be exposed.

**Security Test Case:**
1. As an external attacker, set the active language by modifying the browser’s `Accept-Language` header, a cookie, or a URL parameter.
2. Access a page that renders a translation field where fallback values are in use (for example, a public-facing page or an admin preview).
3. Observe whether the page returns a translation value from a fallback language that is not the intended default.
4. Compare the output to the expected translation to verify if unauthorized data is being disclosed.

### Vulnerability 4: Weak Default SECRET_KEY in Django Settings

**Description:**
In the settings file (`modeltranslation/tests/settings.py`), the `SECRET_KEY` is hardcoded as a predictable string of 64 zeros (`"0" * 64`). If this default is used in any deployment (including accidentally in production), an attacker who knows the key can forge cryptographic signatures. This weak key undermines Django’s security functions, including session signing, CSRF protection, and integrity of signed cookies.

**Impact:**
A known, weak `SECRET_KEY` enables an attacker to craft or tamper with session cookies and CSRF tokens, potentially leading to session hijacking, unauthorized access, and the circumvention of other security mechanisms—ultimately compromising user data and application integrity.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- The weak default is provided only in a testing settings file and is not meant for production deployment.
- Repository documentation and development guidelines warn users not to deploy with the default settings.

**Missing Mitigations:**
- There is no enforcement or automated check to require a secure, randomly generated key be provided for production deployments.
- Lacking are fail‑safe measures (for example, environment‑based configuration that securely aborts if a custom SECRET_KEY is not set).

**Preconditions:**
- The application is deployed using the default settings without overriding the `SECRET_KEY`.
- The deployed instance is publicly accessible, allowing an attacker to leverage the known secret.

**Source Code Analysis:**
- In `modeltranslation/tests/settings.py`, the `SECRET_KEY` is set via the expression `"0" * 64`, resulting in a constant, predictable key.
- Because this key is shared across all deployments using the unmodified test settings, cryptographic signing is effectively disabled.

**Security Test Case:**
1. Deploy the application using the current settings file without modifications.
2. Confirm that the `SECRET_KEY` is the predictable string of 64 zeros.
3. Use the known key to craft a forged session cookie or CSRF token (by mimicking Django’s signing process).
4. Submit a request to the application using the forged cookie or token.
5. Verify that the application accepts the simulated authentication or token—confirming that the weak secret facilitates signature tampering.