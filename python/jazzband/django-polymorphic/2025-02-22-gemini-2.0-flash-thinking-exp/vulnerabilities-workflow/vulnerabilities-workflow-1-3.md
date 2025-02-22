### Vulnerability List

*   #### Vulnerability Name: Polymorphic Query Field Path Injection

    *   **Description:**
        1.  An attacker can craft a malicious field path in a Django QuerySet filter, order\_by, annotate, or aggregate operation when using `django-polymorphic`.
        2.  The `translate_polymorphic_field_path` function in `polymorphic/query_translate.py` is intended to translate "ModelX\_\_\_field" style field paths into Django's ORM syntax (e.g., "modela\_\_modelb\_\_modelc\_\_field").
        3.  However, the function does not sufficiently sanitize or validate the `classname` part of the field path (before the "\_\_\_").
        4.  By injecting special characters or SQL keywords into the `classname`, an attacker might be able to manipulate the generated SQL query in unintended ways. Although direct SQL injection is unlikely due to Django's ORM, it could potentially lead to unexpected query behavior, data leakage, or other ORM-level bypasses depending on the specific injection.
        5.  For example, an attacker might attempt to use class names like `'); DELETE FROM auth_user; --` or similar within the field path.

    *   **Impact:**
        Potentially High. Although direct SQL injection is unlikely, manipulating the query structure through field path injection could lead to:
        *   **Data Leakage:** By altering the query logic, an attacker might be able to extract data they are not authorized to access.
        *   **ORM-Level Bypass:**  It is possible that carefully crafted injections could bypass certain ORM security mechanisms or application-level access controls.
        *   **Unexpected Application Behavior:** Malicious field paths could cause the application to behave in unpredictable ways, possibly leading to further vulnerabilities or application errors.

    *   **Vulnerability Rank:** High

    *   **Currently Implemented Mitigations:**
        None. The code performs basic parsing of the field path but lacks input sanitization or validation against malicious class names.

    *   **Missing Mitigations:**
        *   **Input Sanitization/Validation:** Implement robust sanitization or validation in `translate_polymorphic_field_path` to ensure the `classname` part of the field path only contains valid characters (e.g., alphanumeric and underscores) and does not include SQL keywords or special characters that could be used for injection.
        *   **Consider using a whitelist approach:** Instead of trying to blacklist malicious patterns, a safer approach would be to explicitly whitelist allowed characters for class names and enforce this whitelist during field path translation.

    *   **Preconditions:**
        *   The application must be using `django-polymorphic` and allow user-controlled input to influence QuerySet operations like `filter()`, `order_by()`, `annotate()`, or `aggregate()` where field paths are used, especially if these operations use the "ModelX\_\_\_field" syntax.
        *   An attacker needs to be able to inject malicious strings into the field path parameters of these QuerySet operations.

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
            *   The function takes `field_path` as input.
            *   It partitions the `field_path` by "___" to extract `classname`, `sep`, and `pure_field_path`.
            *   It checks for negation prefix "-" in `classname`.
            *   It attempts to resolve the `model` based on `classname`, either using `apps.get_model` if "__" is present or by looking up submodels.
            *   It constructs `basepath` and finally `newpath` by concatenating parts.
            *   The unsanitized `classname` is used in model lookups and path construction, which can be manipulated by the attacker.

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