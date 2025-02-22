## Vulnerability List:

- Vulnerability Name: Insecure Historical Data Access due to Missing Permission Enforcement

- Description:
    1. An attacker can potentially access historical data of Django models even without explicit "view_history" or "change_history" permissions if `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` setting is not enabled.
    2. The `SimpleHistoryAdmin` class in `admin.py` checks for permissions using `has_view_history_or_change_history_permission`.
    3. This function, when `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` is False (default), falls back to `has_view_or_change_permission`, which are the standard Django model permissions ("view" and "change").
    4. If a user has "view" or "change" permission on the base model, they might be able to access historical data through admin history views even if they are not intended to have specific historical data access permissions.
    5. This bypasses the intended granular control over historical data access, potentially exposing sensitive historical information to unauthorized users who have general model view/change permissions.

- Impact:
    - Unauthorized access to historical data.
    - Potential information disclosure if historical records contain sensitive information that users with base model "view" or "change" permissions should not access.
    - Privilege escalation if users can view historical changes they are not authorized to see, potentially revealing past states of data or actions performed by other users.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    - None by default. The project relies on the Django admin permission system, but does not enforce specific history model permissions by default.

- Missing Mitigations:
    - Enable `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS = True` in Django settings to enforce specific "view_history" and "change_history" permissions on historical models.
    - Clearly document the importance of enabling `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` in the project's documentation and highlight the security implications of not enabling it.

- Preconditions:
    - `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` setting is set to `False` (default).
    - An attacker has "view" or "change" permission on a model that is tracked by `simple-history`.
    - The attacker has access to the Django admin interface.

- Source Code Analysis:
    1. **File: /code/simple_history/admin.py**
    2. Inspect `SimpleHistoryAdmin.has_view_history_or_change_history_permission(self, request, obj=None)` function:
    ```python
    def has_view_history_or_change_history_permission(self, request, obj=None):
        if self.enforce_history_permissions: # Line 327
            return self.has_view_history_permission(
                request, obj
            ) or self.has_change_history_permission(request, obj)
        return self.has_view_or_change_permission(request, obj) # Line 330
    ```
    3. Observe that if `self.enforce_history_permissions` (which is based on `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` setting) is `False`, the function returns `self.has_view_or_change_permission(request, obj)`.
    4. Inspect `SimpleHistoryAdmin.has_view_or_change_permission(request, obj=None)` function:
    ```python
    def has_view_or_change_permission(request, obj=None): # Line 323
        return self.has_view_permission(request, obj) or self.has_change_permission(
            request, obj
        )
    ```
    5. These functions simply check for standard Django "view" and "change" permissions on the base model, not specific history model permissions when `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` is not enabled.
    6. Inspect `SimpleHistoryAdmin.enforce_history_permissions` property:
    ```python
    @property # Line 334
    def enforce_history_permissions(self): # Line 335
        return getattr(
            settings, "SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS", False # Line 336
        )
    ```
    7. Confirm that `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` defaults to `False`.
    8. Conclude that by default, access to history views in `SimpleHistoryAdmin` is controlled by the base model's "view" or "change" permissions, potentially leading to unauthorized access to historical data.

- Security Test Case:
    1. Setup:
        - Ensure `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS` is set to `False` (or not set, to use default).
        - Create a Django model `Poll` and register it with `SimpleHistoryAdmin`.
        - Create two users:
            - User A: Has "view_poll" permission but not "view_historicalpoll" permission.
            - User B: Has "view_poll" and "view_historicalpoll" permissions.
        - Log in as User A into Django admin.
    2. Steps:
        - Navigate to the admin change list view for the `Poll` model.
        - For any `Poll` object, click on the "History" link.
    3. Expected Result:
        - User A should be able to access the history view of the `Poll` object and see historical records, even though they do not have explicit "view_historicalpoll" permission.
    4. Setup for Mitigated Test:
        - Set `SIMPLE_HISTORY_ENFORCE_HISTORY_MODEL_PERMISSIONS = True` in Django settings.
        - Keep User A and User B permission settings the same.
        - Log in as User A into Django admin.
    5. Steps for Mitigated Test:
        - Navigate to the admin change list view for the `Poll` model.
        - For any `Poll` object, click on the "History" link.
    6. Expected Result for Mitigated Test:
        - User A should be denied access to the history view and receive a permission denied error because they lack "view_historicalpoll" permission, demonstrating that permission enforcement is now active.