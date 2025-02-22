### Vulnerability List:

* Vulnerability Name: Unrestricted Access to Event Details via `api_occurrences` API Endpoint

* Description:
    1. An attacker can access the publicly available `/api_occurrences` endpoint.
    2. By providing a `calendar_slug` parameter in the GET request, the attacker can attempt to retrieve event occurrences for a specific calendar.
    3. If the `CHECK_CALENDAR_PERM_FUNC` setting is not properly configured to enforce specific access control policies, the attacker may be able to retrieve event details even for calendars they are not authorized to view.
    4. The API endpoint responds with a JSON payload containing details of all event occurrences within the specified time range for the given calendar. This includes sensitive information such as event titles, descriptions, start and end times, creator details, and calendar information.

* Impact:
    Unauthorized access to sensitive event details. Depending on the nature of events stored, this could lead to:
    - Privacy violations by exposing personal or confidential meeting details.
    - Competitive disadvantage if calendar data reveals business strategies or schedules.
    - Security breaches if event descriptions contain sensitive information or links.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    - The `@check_calendar_permissions` decorator is applied to the `api_occurrences` view function in `/code/schedule/views.py`.
    - This decorator uses the `CHECK_CALENDAR_PERM_FUNC` setting to perform calendar-level permission checks.

* Missing Mitigations:
    - Proper configuration of the `CHECK_CALENDAR_PERM_FUNC` setting in the project's `settings.py` file to enforce specific and robust access control policies for calendars.
    - The default implementation of `CHECK_CALENDAR_PERM_FUNC` in `/code/schedule/settings.py` only checks for user authentication (`user.is_authenticated`), which is insufficient to restrict access based on roles or specific calendar permissions.
    - Missing input validation for `calendar_slug` to prevent potential abuse or unexpected behavior.

* Preconditions:
    - A publicly accessible instance of the Django Scheduler application is running.
    - At least one calendar exists with events scheduled.
    - The `CHECK_CALENDAR_PERM_FUNC` setting is either not configured in `settings.py`, or it is using the default implementation that only verifies user authentication, without further authorization checks.

* Source Code Analysis:
    - File: `/code/schedule/views.py`
        ```python
        @check_calendar_permissions
        def api_occurrences(request):
            # ... function implementation ...
        ```
        - The `api_occurrences` function is decorated with `@check_calendar_permissions`.
    - File: `/code/schedule/utils.py`
        ```python
        def check_calendar_permissions(view_func):
            def _checklogin(request, calendar_slug=None, *args, **kwargs):
                if calendar_slug is not None:
                    calendar = get_object_or_404(Calendar, slug=calendar_slug)
                else:
                    calendar = None
                if not CHECK_CALENDAR_PERM_FUNC(calendar, request.user): # CHECK_CALENDAR_PERM_FUNC is called here
                    return HttpResponseRedirect(reverse("auth_login") + "?next=" + request.path)
                return view_func(request, calendar_slug, *args, **kwargs)
            return wraps(view_func)(_checklogin)
        ```
        - The `check_calendar_permissions` decorator retrieves the `CHECK_CALENDAR_PERM_FUNC` setting and executes it.
    - File: `/code/schedule/settings.py`
        ```python
        CHECK_CALENDAR_PERM_FUNC = getattr(settings, "CHECK_CALENDAR_PERM_FUNC", None)

        if not CHECK_CALENDAR_PERM_FUNC:

            def check_calendar_permission(ob, user):
                return user.is_authenticated # Default implementation: only checks for authentication

            CHECK_CALENDAR_PERM_FUNC = check_calendar_permission
        ```
        - The default `CHECK_CALENDAR_PERM_FUNC` only verifies if the user is authenticated, not if they have specific permissions to access the requested calendar. This means that any authenticated user can potentially access event data from any calendar by knowing its `calendar_slug`.

* Security Test Case:
    1. Create two test users: `testuser1` (unprivileged) and `adminuser` (administrator).
    2. Create two calendars: `public_calendar` and `private_calendar`. Add some events to both calendars. Configure `private_calendar` to have restricted access, if such configuration is possible within the application (if not, assume default permissions apply).
    3. Log in to the application as `testuser1`.
    4. As `testuser1`, access the `/api_occurrences` endpoint for `public_calendar` using its `calendar_slug` and a suitable time range (e.g., `start=2024-01-01&end=2024-12-31`). Verify that the response contains event details for `public_calendar`.
    5. As `testuser1`, attempt to access the `/api_occurrences` endpoint for `private_calendar` using its `calendar_slug` and the same time range.
    6. Observe the response. If `testuser1` can successfully retrieve event details for `private_calendar`, it confirms the vulnerability.
    7. Expected vulnerable outcome: `testuser1` should be able to retrieve event details for both `public_calendar` and `private_calendar` because the default permission check only validates authentication and not calendar-specific authorization.