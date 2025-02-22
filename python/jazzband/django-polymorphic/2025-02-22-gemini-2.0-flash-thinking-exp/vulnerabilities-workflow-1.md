## Combined Vulnerability Report

### Vulnerability List

*   #### Vulnerability Name: Polymorphic Form Type Confusion

    *   **Description:**
        1.  An attacker interacts with a polymorphic formset or admin interface designed to handle multiple child model types. This is common in Django Admin when using polymorphic inlines or forms.
        2.  When submitting data for a new object or modifying an existing one, the attacker manipulates the `polymorphic_ctype` hidden field value in the form data. This is done to specify a different child model type than what is intended or expected by the application in the current context.
        3.  The application, upon receiving the manipulated form data, incorrectly uses the form and validation logic associated with the attacker-specified `polymorphic_ctype`. This occurs because the application insufficiently validates if the submitted `polymorphic_ctype` is appropriate for the current operation and context.
        4.  This type confusion can lead to the application bypassing intended validation rules, as it applies the validation logic of the attacker-chosen model type instead of the intended one. It may also result in data integrity issues, as data might be saved in a format or structure that is inconsistent with the originally intended model type. In some cases, this can trigger backend errors due to data type mismatches or constraint violations. This is especially relevant in Django Admin contexts using polymorphic inlines as observed in `polymorphic/admin/inlines.py`.

    *   **Impact:**
        - Data integrity issues: Data can be saved in a manner inconsistent with the intended model's constraints and data types, leading to corrupted or invalid data.
        - Validation bypass: Intended validation rules for a specific model type can be bypassed by coercing the application to use a different model type's form and validation process.
        - Backend errors: Type mismatches or constraint violations can occur in the application's backend when processing data under the wrong model type assumption, potentially leading to application instability or errors.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:**
        - In `BasePolymorphicModelFormSet._construct_form` (as seen in the context of `polymorphic/admin/inlines.py` which uses `BasePolymorphicInlineFormSet`), there is a check to ensure that the resolved model based on `polymorphic_ctype` is present in `self.child_forms`. This prevents the use of completely unregistered content types within the formset.
        - In `PolymorphicParentModelAdmin._get_real_admin_by_model`, a check verifies that the model class associated with the `ct_id` is within `self._child_models`. This restricts admin access to only those models intended as children within the polymorphic admin structure, as seen in the usage of `PolymorphicChildModelFilter` in `polymorphic/admin/filters.py` which interacts with `PolymorphicParentModelAdmin`.

    *   **Missing Mitigations:**
        - The project lacks context-aware validation of the `polymorphic_ctype` during form submission. While checks exist to ensure the type is registered, there's no mechanism to enforce that the submitted `polymorphic_ctype` is the *correct* or *expected* type for the current operation. The system does not verify if the chosen type aligns with the intended model in the specific workflow or context where the form is being used.

    *   **Preconditions:**
        - The Django application must be using the `django-polymorphic` library.
        - Polymorphic models are implemented with formsets or admin interfaces, including admin inlines as described in `polymorphic/admin/inlines.py`, that handle multiple child model types.
        - There are at least two child models registered within a polymorphic formset or admin view.
        - Forms for different child models must have overlapping field names but different validation rules, data type expectations, or field behaviors for the vulnerability to be exploitable.

    *   **Source Code Analysis:**
        1.  **`polymorphic/formsets/models.py:BasePolymorphicModelFormSet._construct_form`**:
            ```python
            def _construct_form(self, i, **kwargs):
                # ...
                if self.is_bound:
                    # ...
                    try:
                        ct_id = int(self.data[f"{prefix}-polymorphic_ctype"])
                    except (KeyError, ValueError):
                        raise ValidationError(
                            f"Formset row {prefix} has no 'polymorphic_ctype' defined!"
                        )

                    model = ContentType.objects.get_for_id(ct_id).model_class()
                    if model not in self.child_forms:
                        # Perform basic validation, as we skip the ChoiceField here.
                        raise UnsupportedChildType(
                            f"Child model type {model} is not part of the formset"
                        )
                # ...
                form_class = self.get_form_class(model)
                form = form_class(**defaults)
                # ...
            ```
            - This code snippet, relevant to formset handling in admin inlines as seen in `polymorphic/admin/inlines.py`, shows that the `model` is determined by the `ct_id` from user-provided `self.data`.
            - It checks if the resolved `model` is in `self.child_forms`, which is a basic validation.
            - The form is then constructed using `self.get_form_class(model)`, which dynamically selects the form based on the attacker-influenced `model`.

        2.  **`polymorphic/admin/parentadmin.py:PolymorphicParentModelAdmin._get_real_admin_by_ct`**:
            ```python
            def _get_real_admin_by_ct(self, ct_id, super_if_self=True):
                try:
                    ct = ContentType.objects.get_for_id(ct_id)
                except ContentType.DoesNotExist as e:
                    raise Http404(e)  # Handle invalid GET parameters

                model_class = ct.model_class()
                if not model_class:
                    # Handle model deletion
                    app_label, model = ct.natural_key()
                    raise Http404(f"No model found for '{app_label}.{model}'.")

                return self._get_real_admin_by_model(model_class, super_if_self=super_if_self)
            ```
            - This function retrieves the `model_class` based on `ct_id` from the request.
            - It performs a check in `_get_real_admin_by_model`: `if model_class not in self._child_models:`, but this is only for admin access control, not form processing context validation, and is used in contexts like filtering in `PolymorphicChildModelFilter` from `polymorphic/admin/filters.py`.

    *   **Security Test Case:**
        1.  **Setup:** Define two models, `ModelTypeA` and `ModelTypeB`, both inheriting from a base polymorphic model. `ModelTypeA` has a field `data_field` which is intended to store integer values and has integer validation. `ModelTypeB` also has a field named `data_field`, but it's intended to store strings and has string-based validation (e.g., max length). Create a polymorphic formset (potentially within a Django Admin inline as demonstrated by `polymorphic/admin/inlines.py`) that includes forms for both `ModelTypeA` and `ModelTypeB`.
        2.  **Access Form:** Render the polymorphic formset in a test view (or within the Django Admin change form). Inspect the HTML to identify the `polymorphic_ctype` values for `ModelTypeA` (let's say `ct_id_A`) and `ModelTypeB` (say `ct_id_B`).
        3.  **Prepare Malicious Payload:** Prepare form data intended for `ModelTypeA`, specifically for the `data_field`, input a string value (e.g., "test_string"). This should normally fail validation for `ModelTypeA` because it expects an integer.
        4.  **Type Confusion Attack:** In the form data, manipulate the `polymorphic_ctype` field to `ct_id_B` while keeping the data for `data_field` as "test_string". Submit this manipulated form data.
        5.  **Observe Outcome:** Check if the form submission is successful. If it is, it indicates that the validation for `ModelTypeB` (string validation) was applied instead of `ModelTypeA` (integer validation).
        6.  **Verify Data Integrity:** Inspect the created object in the database. If an object of type `ModelTypeB` is created with "test_string" in `data_field`, and no validation error was raised, it confirms the vulnerability. Furthermore, attempt to retrieve and use this object as if it were intended to be `ModelTypeA`. Observe if any backend errors or unexpected behavior occur due to the data type mismatch.

    *   **Recommended Mitigations:**
        - **Contextual `polymorphic_ctype` Validation:** In `BasePolymorphicModelFormSet.clean()` method, or within the admin's `save_model()` method, implement validation to ensure that the submitted `polymorphic_ctype` is not only within the allowed child types but is also consistent with the expected type for the specific operation or context. This might involve:
            - Defining expected `polymorphic_ctype` for different form submission contexts.
            - Comparing the submitted `polymorphic_ctype` against the expected type and raising a validation error if they do not match.
        - **Server-Side Type Enforcement:** Beyond form-level validation, enforce the intended model type on the server-side before object creation or modification. This could involve checking the intended model type in the view logic and ensuring that the `polymorphic_ctype` of the created/modified object matches this intended type, regardless of the submitted form data.
        - **Consider Removing Client-Side Type Choice (If Applicable):** If the application logic dictates the polymorphic type based on the context (and not user choice), consider removing the client-side choice or making the `polymorphic_ctype` field truly hidden and programmatically set server-side, thus preventing client-side manipulation.

---

*   #### Vulnerability Name: Hardcoded Secret Key and Debug Mode Enabled in Production Settings

    *   **Description:**
        The example project’s production settings file (located at `/code/example/example/settings.py`) is configured with a hardcoded secret key and has `DEBUG = True`. An external attacker who discovers these settings (for example, when this open–source example is deployed as is) can leverage the known secret to forge session cookies, tamper with password reset tokens, or manipulate other security–sensitive data. In addition, with debug mode enabled, any unhandled error could reveal full stack traces and internal configuration details—greatly aiding an attacker in further exploiting the system.

    *   **Impact:**
        *Critical.*
        If deployed unchanged in production, an attacker may gain:
        - The ability to forge or abuse cryptographically signed cookies,
        - Access to internal error messages that disclose file paths, database configurations, and portions of the source code,
        - Opportunities to escalate privileges or tailor further attacks using the exposed internal details.

    *   **Vulnerability Rank:** Critical

    *   **Currently Implemented Mitigations:**
        - A testing settings file (`/code/polymorphic_test_settings.py`) sets `DEBUG = False` and uses a simplified secret; however, this is only intended for tests.

    *   **Missing Mitigations:**
        - The secret key must be sourced from an environment variable or a secure configuration management system, not hardcoded in the source.
        - `DEBUG` must be set to `False` in any production deployment.
        - Additional production hardening (e.g. secure cookies, HSTS, proper logging, etc.) should be applied.

    *   **Preconditions:**
        - The application is deployed using the settings file at `/code/example/example/settings.py` without modification in a publicly accessible production environment.

    *   **Source Code Analysis:**
        - In `/code/example/example/settings.py`, the file begins with:
            ```python
            DEBUG = True
            …
            SECRET_KEY = "5$f%)&a4tc*bg(79+ku!7o$kri-duw99@hq_)va^_kaw9*l)!7"
            ```
            Since these values are not overridden based on production criteria, any instance built with this file carries the risk.

    *   **Security Test Case:**
        1.  Deploy the example application using the current production settings (with `DEBUG = True` and the hardcoded `SECRET_KEY`).
        2.  Cause an error (for example, by visiting a non-existent URL) and observe that Django renders a detailed debug page exposing internal configuration and stack trace information.
        3.  Using the known `SECRET_KEY`, attempt to craft a forged session cookie or password reset token, then submit it to the application to determine if cryptographic verification is bypassed.
        4.  Verify that modifying the settings to read the `SECRET_KEY` from a secure environment and setting `DEBUG = False` prevents these exploits.

---

*   #### Vulnerability Name: Missing ALLOWED_HOSTS Configuration Leading to Host Header Attacks

    *   **Description:**
        In the production settings file (`/code/example/example/settings.py`), there is no explicit `ALLOWED_HOSTS` setting defined. When the application is deployed without imposing an allowed list of domain names—even if `DEBUG` is later set to `False`—Django may not correctly validate the Host header of incoming requests. An attacker might supply a malicious Host header and, in certain circumstances, exploit the misconfiguration to enable host header injection attacks (which can lead to issues such as cache poisoning, spoofed password reset URLs, or phishing).

    *   **Impact:**
        *High.*
        A missing or improperly configured `ALLOWED_HOSTS` setting can allow an attacker to control which host headers are accepted by Django. This misconfiguration may result in compromised session security and allow an attacker to misdirect user trust.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:**
        - There is no mitigation implemented in the production configuration; `ALLOWED_HOSTS` is not defined in `/code/example/example/settings.py`.

    *   **Missing Mitigations:**
        - An explicit list of allowed domain names (or IP addresses) must be enforced via the `ALLOWED_HOSTS` setting when deploying with `DEBUG = False`.
        - Where possible, filtering or normalization of Host headers should be reinforced by middleware or a reverse proxy.

    *   **Preconditions:**
        - The application is deployed in production with `DEBUG` turned off while lacking an appropriate `ALLOWED_HOSTS` configuration.

    *   **Source Code Analysis:**
        - In `/code/example/example/settings.py`, there is no definition such as:
            ```python
            ALLOWED_HOSTS = ['yourdomain.com']
            ```
            Without an explicit list, Django’s host header validation may be bypassed or misconfigured when DEBUG is disabled.

    *   **Security Test Case:**
        1.  Deploy the application with the current settings, then set `DEBUG = False` but leave `ALLOWED_HOSTS` undefined.
        2.  Send an HTTP request with an arbitrary Host header (e.g., `evil.com`).
        3.  Confirm that Django does not reject the request as it would if a proper `ALLOWED_HOSTS` list were configured.
        4.  Verify that forged host values in generated links (such as those in password reset emails) use the malicious host.
        5.  After securing the configuration with a valid `ALLOWED_HOSTS` list, check that requests with invalid Host headers are correctly rejected.

---

*   #### Vulnerability Name: Unpinned Dependency Versions in Build System

    *   **Description:**
        The project dependency configuration file (`/code/pyproject.toml`) specifies a requirement for Django using an open-ended version constraint (`django>=3.2`) without an upper bound. This unpinned dependency version range means that any future release of Django that meets the minimum version requirement could be installed—even if it later contains breaking changes or has been compromised. An attacker who manages to subvert the package supply chain could potentially publish a malicious Django version that still satisfies the version constraint, thereby introducing harmful code into the production environment.

    *   **Impact:**
        *High.*
        If a malicious or vulnerable release of Django is installed due to the unpinned version constraint, the attacker may be able to:
        - Execute malicious code in the context of the application,
        - Bypass or weaken established security controls,
        - Compromise the confidentiality, integrity, and availability of the application and its data.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:**
        - The `/code/pyproject.toml` file lists the dependency as:
            ```toml
            requires = [
                "setuptools",
                "django>=3.2",  # for makemessages
            ]
            ```
            There is no upper bound or explicit version pinning specified.

    *   **Missing Mitigations:**
        - The dependency on Django should be pinned to a narrowly defined version range (for example, `django>=3.2,<3.3`) or a specific version should be used.
        - The project should employ a dependency lock file or include hash verification to ensure only validated package versions are installed.

    *   **Preconditions:**
        - The application is built and deployed in an environment where dependency resolution is based solely on the open-ended version specification in `/code/pyproject.toml`, without additional mechanisms (such as a lock file) to enforce a specific Django version.
        - An attacker is able to compromise the package supply chain or repository hosting Django such that a malicious version within the allowed range is published.

    *   **Source Code Analysis:**
        - In the `/code/pyproject.toml` file under the `[build-system]` section, Django is required as follows:
            ```toml
            requires = [
                "setuptools",
                "django>=3.2",  # for makemessages
            ]
            ```
            The absence of an upper bound means that any Django version above 3.2 is acceptable. This creates a window of opportunity for an attacker to introduce a malicious release that meets this constraint.

    *   **Security Test Case:**
        1.  In a controlled testing environment that simulates dependency resolution based on `/code/pyproject.toml`, configure the package manager to resolve dependencies from a custom repository.
        2.  Publish a mock Django release that satisfies the version constraint (`>=3.2`) but includes a deliberate malicious payload.
        3.  Install the application dependencies and verify that the malicious Django package is retrieved and its code is executed at runtime.
        4.  Observe any deviations in application behavior (such as unauthorized actions or altered processing logic).
        5.  Reconfigure the dependency requirement to pin the Django version (or use a lock file) and confirm that the malicious package is no longer installed.

---

*   #### Vulnerability Name: Polymorphic Query Field Path Injection

    *   **Description:**
        1.  An attacker can craft a malicious field path in a Django QuerySet filter, order\_by, annotate, or aggregate operation when using `django-polymorphic`.
        2.  The `translate_polymorphic_field_path` function in `polymorphic/query_translate.py` is intended to translate "ModelX\_\_\_field" style field paths into Django's ORM syntax (e.g., "modela\_\_modelb\_\_modelc\_\_field").
        3.  However, the function does not sufficiently sanitize or validate the `classname` part of the field path (before the "\_\_\_").
        4.  By injecting special characters or SQL keywords into the `classname`, an attacker might be able to manipulate the generated SQL query in unintended ways. Although direct SQL injection is unlikely due to Django's ORM, it could potentially lead to unexpected query behavior, data leakage, or other ORM-level bypasses depending on the specific injection.
        5.  For example, an attacker might attempt to use class names like `'); DELETE FROM auth_user; --` or similar within the field path.

    *   **Impact:**
        Potentially High. Although direct SQL injection is unlikely, manipulating the query structure through field path injection could lead to:
        -   **Data Leakage:** By altering the query logic, an attacker might be able to extract data they are not authorized to access.
        -   **ORM-Level Bypass:**  It is possible that carefully crafted injections could bypass certain ORM security mechanisms or application-level access controls.
        -   **Unexpected Application Behavior:** Malicious field paths could cause the application to behave in unpredictable ways, possibly leading to further vulnerabilities or application errors.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:**
        - None. The code performs basic parsing of the field path but lacks input sanitization or validation against malicious class names.

    *   **Missing Mitigations:**
        -   **Input Sanitization/Validation:** Implement robust sanitization or validation in `translate_polymorphic_field_path` to ensure the `classname` part of the field path only contains valid characters (e.g., alphanumeric and underscores) and does not include SQL keywords or special characters that could be used for injection.
        -   **Consider using a whitelist approach:** Instead of trying to blacklist malicious patterns, a safer approach would be to explicitly whitelist allowed characters for class names and enforce this whitelist during field path translation.

    *   **Preconditions:**
        -   The application must be using `django-polymorphic` and allow user-controlled input to influence QuerySet operations like `filter()`, `order_by()`, `annotate()`, or `aggregate()` where field paths are used, especially if these operations use the "ModelX\_\_\_field" syntax.
        -   An attacker needs to be able to inject malicious strings into the field path parameters of these QuerySet operations.

    *   **Source Code Analysis:**
        1.  **File:** `/code/polymorphic/query_translate.py`
        2.  **Function:** `translate_polymorphic_field_path(queryset_model, field_path)`
        3.  **Code Snippet:**
            ```python
            def translate_polymorphic_field_path(queryset_model, field_path):
                """
                Translate a field path from a keyword argument, as used for
                PolymorphicQuerySet.filter()-like functions (and Q objects).
                Supports leading '-' (for order_by args).

                E.g.: if queryset_model is ModelA, then "ModelC___field3" is translated
                into modela__modelb__modelc__field3.
                Returns: translated path (unchanged, if no translation needed)
                """
                if not isinstance(field_path, str):
                    raise ValueError(f"Expected field name as string: {field_path}")

                classname, sep, pure_field_path = field_path.partition("___")
                if not sep:
                    return field_path
                assert classname, f"PolymorphicModel: {field_path}: bad field specification"

                negated = False
                if classname[0] == "-":
                    negated = True
                    classname = classname.lstrip("-")

                if "__" in classname:
                    # the user has app label prepended to class name via __ => use Django's get_model function
                    appname, sep, classname = classname.partition("__")
                    model = apps.get_model(appname, classname)
                    assert model, f"PolymorphicModel: model {model.__name__} (in app {appname}) not found!"
                    if not issubclass(model, queryset_model):
                        e = (
                            'PolymorphicModel: queryset filter error: "'
                            + model.__name__
                            + '" is not derived from "'
                            + queryset_model.__name__
                            + '"'
                        )
                        raise AssertionError(e)

                else:
                    # the user has only given us the class name via ___
                    # => select the model from the sub models of the queryset base model

                    # Test whether it's actually a regular relation__ _fieldname (the field starting with an _)
                    # so no tripple ClassName___field was intended.
                    try:
                        # This also retreives M2M relations now (including reverse foreign key relations)
                        field = queryset_model._meta.get_field(classname)

                        if isinstance(field, (RelatedField, ForeignObjectRel)):
                            # Can also test whether the field exists in the related object to avoid ambiguity between
                            # class names and field names, but that never happens when your class names are in CamelCase.
                            return field_path  # No exception raised, field does exist.
                    except FieldDoesNotExist:
                        pass

                    submodels = _get_all_sub_models(queryset_model)
                    model = submodels.get(classname, None)
                    assert model, f"PolymorphicModel: model {classname} not found (not a subclass of {queryset_model.__name__})!"

                basepath = _create_base_path(queryset_model, model)

                if negated:
                    newpath = "-"
                else:
                    newpath = ""

                newpath += basepath
                if basepath:
                    newpath += "__"

                newpath += pure_field_path
                return newpath
            ```
        4.  **Vulnerability Point:** The `classname` variable, extracted from `field_path.partition("___")`, is used to look up models and construct the translated path. There is no sanitization of this `classname` to prevent injection of malicious strings.
        5.  **Code Flow:**
            -   The function takes `field_path` as input.
            -   It partitions the `field_path` by "___" to extract `classname`, `sep`, and `pure_field_path`.
            -   It checks for negation prefix "-" in `classname`.
            -   It attempts to resolve the `model` based on `classname`, either using `apps.get_model` if "__" is present or by looking up submodels.
            -   It constructs `basepath` and finally `newpath` by concatenating parts.
            -   The unsanitized `classname` is used in model lookups and path construction, which can be manipulated by the attacker.

    *   **Security Test Case:**
        1.  **Pre-requisite:** Set up a Django project with `django-polymorphic` installed and the example `pexp` app (if available, otherwise use any app using polymorphic models). Ensure the Django development server is running and Django admin is enabled.
        2.  **Goal:** Inject a malicious class name into a filter operation via Django Admin list view to observe if it causes unexpected behavior or errors.
        3.  **Steps:**
            a.  Log in to the Django admin interface as a superuser.
            b.  Navigate to the list view of a model that utilizes `django-polymorphic` (e.g., Project list view in `pexp` app, or any other polymorphic model list view in your test project).
            c.  Identify a filterable field in the list view. If list filters are not configured to use field paths directly, you might need to customize `list_filter` in your `ModelAdmin` to expose such filtering. Alternatively, you can try to craft a URL to directly manipulate the query parameters.
            d.  Attempt to inject a malicious class name into a filter parameter in the URL. For example, if the filter URL parameter is like `?ModelX___field__exact=value`, try modifying it to `?');DELETE FROM auth_user;--___field__exact=value`.
            e.  Specifically, if list filters are based on model fields, try to add a filter in the admin URL that uses the "ModelName\_\_\_fieldname" syntax and inject the malicious payload into "ModelName" part. For instance, if you are filtering on a field related to `BlogA` model named `info`, try a URL like: `/admin/tests/blogbase/?BlogA___info__contains=test` and then modify it to `/admin/tests/blogbase/?');DELETE FROM auth_user;--___info__contains=test`.
            f.  Observe the server response and any database errors. Check if the application behaves unexpectedly or if any data manipulation occurs that should not have.
            g.  A successful test would be if injecting a malicious `classname` in the field path leads to a database error or unexpected query execution beyond just "model not found" errors, indicating potential injection.  It's important to note that proving direct SQL injection is unlikely, but demonstrating manipulation of the query structure or ORM behavior is the goal.
            h.  Examine the Django debug output or server logs for any unusual SQL queries or errors that arise from the injected payload.

    *   **Notes from new PROJECT FILES analysis:**
        The newly provided files (`/code/polymorphic/admin/filters.py`, `/code/polymorphic/admin/forms.py`, `/code/polymorphic/admin/inlines.py`, `/code/pyproject.toml`) related to formsets and admin functionalities do not introduce new vulnerabilities nor provide mitigations for the "Polymorphic Query Field Path Injection" vulnerability. The core issue remains in the `translate_polymorphic_field_path` function within `/code/polymorphic/query_translate.py`, which is not addressed in these files. Therefore, the vulnerability remains unmitigated.