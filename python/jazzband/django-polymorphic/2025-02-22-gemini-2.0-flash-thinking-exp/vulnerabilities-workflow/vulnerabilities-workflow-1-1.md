## Vulnerability Report

### Vulnerability List

- Polymorphic Form Type Confusion

### Vulnerability: Polymorphic Form Type Confusion
- **Vulnerability Name:** Polymorphic Form Type Confusion
- **Description:**
    1. An attacker interacts with a polymorphic formset or admin interface designed to handle multiple child model types. This is common in Django Admin when using polymorphic inlines or forms.
    2. When submitting data for a new object or modifying an existing one, the attacker manipulates the `polymorphic_ctype` hidden field value in the form data. This is done to specify a different child model type than what is intended or expected by the application in the current context.
    3. The application, upon receiving the manipulated form data, incorrectly uses the form and validation logic associated with the attacker-specified `polymorphic_ctype`. This occurs because the application insufficiently validates if the submitted `polymorphic_ctype` is appropriate for the current operation and context.
    4. This type confusion can lead to the application bypassing intended validation rules, as it applies the validation logic of the attacker-chosen model type instead of the intended one. It may also result in data integrity issues, as data might be saved in a format or structure that is inconsistent with the originally intended model type. In some cases, this can trigger backend errors due to data type mismatches or constraint violations. This is especially relevant in Django Admin contexts using polymorphic inlines as observed in `polymorphic/admin/inlines.py`.

- **Impact:**
    - Data integrity issues: Data can be saved in a manner inconsistent with the intended model's constraints and data types, leading to corrupted or invalid data.
    - Validation bypass: Intended validation rules for a specific model type can be bypassed by coercing the application to use a different model type's form and validation process.
    - Backend errors: Type mismatches or constraint violations can occur in the application's backend when processing data under the wrong model type assumption, potentially leading to application instability or errors.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - In `BasePolymorphicModelFormSet._construct_form` (as seen in the context of `polymorphic/admin/inlines.py` which uses `BasePolymorphicInlineFormSet`), there is a check to ensure that the resolved model based on `polymorphic_ctype` is present in `self.child_forms`. This prevents the use of completely unregistered content types within the formset.
    - In `PolymorphicParentModelAdmin._get_real_admin_by_model`, a check verifies that the model class associated with the `ct_id` is within `self._child_models`. This restricts admin access to only those models intended as children within the polymorphic admin structure, as seen in the usage of `PolymorphicChildModelFilter` in `polymorphic/admin/filters.py` which interacts with `PolymorphicParentModelAdmin`.

- **Missing Mitigations:**
    - The project lacks context-aware validation of the `polymorphic_ctype` during form submission. While checks exist to ensure the type is registered, there's no mechanism to enforce that the submitted `polymorphic_ctype` is the *correct* or *expected* type for the current operation. The system does not verify if the chosen type aligns with the intended model in the specific workflow or context where the form is being used.

- **Preconditions:**
    - The Django application must be using the `django-polymorphic` library.
    - Polymorphic models are implemented with formsets or admin interfaces, including admin inlines as described in `polymorphic/admin/inlines.py`, that handle multiple child model types.
    - There are at least two child models registered within a polymorphic formset or admin view.
    - Forms for different child models must have overlapping field names but different validation rules, data type expectations, or field behaviors for the vulnerability to be exploitable.

- **Source Code Analysis:**
    1. **`polymorphic/formsets/models.py:BasePolymorphicModelFormSet._construct_form`**:
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

    2. **`polymorphic/admin/parentadmin.py:PolymorphicParentModelAdmin._get_real_admin_by_ct`**:
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

- **Security Test Case:**
    1. **Setup:** Define two models, `ModelTypeA` and `ModelTypeB`, both inheriting from a base polymorphic model. `ModelTypeA` has a field `data_field` which is intended to store integer values and has integer validation. `ModelTypeB` also has a field named `data_field`, but it's intended to store strings and has string-based validation (e.g., max length). Create a polymorphic formset (potentially within a Django Admin inline as demonstrated by `polymorphic/admin/inlines.py`) that includes forms for both `ModelTypeA` and `ModelTypeB`.
    2. **Access Form:** Render the polymorphic formset in a test view (or within the Django Admin change form). Inspect the HTML to identify the `polymorphic_ctype` values for `ModelTypeA` (let's say `ct_id_A`) and `ModelTypeB` (say `ct_id_B`).
    3. **Prepare Malicious Payload:** Prepare form data intended for `ModelTypeA`, specifically for the `data_field`, input a string value (e.g., "test_string"). This should normally fail validation for `ModelTypeA` because it expects an integer.
    4. **Type Confusion Attack:** In the form data, manipulate the `polymorphic_ctype` field to `ct_id_B` while keeping the data for `data_field` as "test_string". Submit this manipulated form data.
    5. **Observe Outcome:** Check if the form submission is successful. If it is, it indicates that the validation for `ModelTypeB` (string validation) was applied instead of `ModelTypeA` (integer validation).
    6. **Verify Data Integrity:** Inspect the created object in the database. If an object of type `ModelTypeB` is created with "test_string" in `data_field`, and no validation error was raised, it confirms the vulnerability. Furthermore, attempt to retrieve and use this object as if it were intended to be `ModelTypeA`. Observe if any backend errors or unexpected behavior occur due to the data type mismatch.

- **Recommended Mitigations:**
    - **Contextual `polymorphic_ctype` Validation:** In `BasePolymorphicModelFormSet.clean()` method, or within the admin's `save_model()` method, implement validation to ensure that the submitted `polymorphic_ctype` is not only within the allowed child types but is also consistent with the expected type for the specific operation or context. This might involve:
        - Defining expected `polymorphic_ctype` for different form submission contexts.
        - Comparing the submitted `polymorphic_ctype` against the expected type and raising a validation error if they do not match.
    - **Server-Side Type Enforcement:** Beyond form-level validation, enforce the intended model type on the server-side before object creation or modification. This could involve checking the intended model type in the view logic and ensuring that the `polymorphic_ctype` of the created/modified object matches this intended type, regardless of the submitted form data.
    - **Consider Removing Client-Side Type Choice (If Applicable):** If the application logic dictates the polymorphic type based on the context (and not user choice), consider removing the client-side choice or making the `polymorphic_ctype` field truly hidden and programmatically set server-side, thus preventing client-side manipulation.

---