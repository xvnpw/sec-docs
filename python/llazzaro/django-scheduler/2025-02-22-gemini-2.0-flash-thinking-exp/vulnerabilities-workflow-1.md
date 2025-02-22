## Combined Vulnerability List

This document consolidates identified vulnerabilities from multiple reports into a unified list, removing duplicates and providing a comprehensive overview of security concerns.

### Unrestricted Access to Event Details via `api_occurrences` API Endpoint

* **Description:**
    1. An attacker can access the publicly available `/api_occurrences` endpoint.
    2. By providing a `calendar_slug` parameter in the GET request, the attacker can attempt to retrieve event occurrences for a specific calendar.
    3. If the `CHECK_CALENDAR_PERM_FUNC` setting is not properly configured to enforce specific access control policies, the attacker may be able to retrieve event details even for calendars they are not authorized to view.
    4. The API endpoint responds with a JSON payload containing details of all event occurrences within the specified time range for the given calendar. This includes sensitive information such as event titles, descriptions, start and end times, creator details, and calendar information.

* **Impact:**
    Unauthorized access to sensitive event details. Depending on the nature of events stored, this could lead to:
    - Privacy violations by exposing personal or confidential meeting details.
    - Competitive disadvantage if calendar data reveals business strategies or schedules.
    - Security breaches if event descriptions contain sensitive information or links.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - The `@check_calendar_permissions` decorator is applied to the `api_occurrences` view function in `/code/schedule/views.py`.
    - This decorator uses the `CHECK_CALENDAR_PERM_FUNC` setting to perform calendar-level permission checks.

* **Missing Mitigations:**
    - Proper configuration of the `CHECK_CALENDAR_PERM_FUNC` setting in the project's `settings.py` file to enforce specific and robust access control policies for calendars.
    - The default implementation of `CHECK_CALENDAR_PERM_FUNC` in `/code/schedule/settings.py` only checks for user authentication (`user.is_authenticated`), which is insufficient to restrict access based on roles or specific calendar permissions.
    - Missing input validation for `calendar_slug` to prevent potential abuse or unexpected behavior.

* **Preconditions:**
    - A publicly accessible instance of the Django Scheduler application is running.
    - At least one calendar exists with events scheduled.
    - The `CHECK_CALENDAR_PERM_FUNC` setting is either not configured in `settings.py`, or it is using the default implementation that only verifies user authentication, without further authorization checks.

* **Source Code Analysis:**
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

* **Security Test Case:**
    1. Create two test users: `testuser1` (unprivileged) and `adminuser` (administrator).
    2. Create two calendars: `public_calendar` and `private_calendar`. Add some events to both calendars. Configure `private_calendar` to have restricted access, if such configuration is possible within the application (if not, assume default permissions apply).
    3. Log in to the application as `testuser1`.
    4. As `testuser1`, access the `/api_occurrences` endpoint for `public_calendar` using its `calendar_slug` and a suitable time range (e.g., `start=2024-01-01&end=2024-12-31`). Verify that the response contains event details for `public_calendar`.
    5. As `testuser1`, attempt to access the `/api_occurrences` endpoint for `private_calendar` using its `calendar_slug` and the same time range.
    6. Observe the response. If `testuser1` can successfully retrieve event details for `private_calendar`, it confirms the vulnerability.
    7. Expected vulnerable outcome: `testuser1` should be able to retrieve event details for both `public_calendar` and `private_calendar` because the default permission check only validates authentication and not calendar-specific authorization.


### Insecure Default Permission Functions Allowing Unauthorized Event Modification

* **Description:**
    1. An attacker logs in to the application with a valid user account.
    2. The attacker identifies the `api_move_or_resize_by_code` API endpoint, used by the calendar to move or resize events and occurrences.
    3. The attacker crafts a POST request to `/api/move_or_resize/` with parameters including `id` (occurrence ID or event ID), `existed` (boolean indicating if it's a persisted occurrence), `delta` (time difference in minutes), `resize` (boolean indicating resize operation), and `event_id` (event ID).
    4. The attacker can modify the parameters such as `id` or `event_id` to target events or occurrences belonging to other users or calendars, even without explicit authorization to do so on those specific events or calendars.
    5. If the default permission settings are in place (or misconfigured), the `CHECK_OCCURRENCE_PERM_FUNC` or `CHECK_EVENT_PERM_FUNC` might only check for user authentication (`user.is_authenticated`) and not verify if the logged-in user has specific rights to modify the targeted event or occurrence.
    6. The server-side code in `_api_move_or_resize_by_code` then proceeds to modify the event or occurrence based on the provided parameters without proper authorization checks beyond basic authentication.
    7. The event or occurrence is moved or resized by the attacker, potentially causing disruption or unauthorized modification of calendar data.
    8. This vulnerability stems from the scheduler’s default permission functions (used for events and occurrences) simply checking that a user is authenticated rather than verifying that the user owns or is otherwise authorized to modify the event. This means that any logged‑in user can modify, move, or delete events and occurrences that do not belong to them.

* **Impact:**
    An attacker who can log in—even with a low‑privilege account—can alter or delete events created by other users. This may result in loss of important scheduling data, unauthorized calendar modifications, and overall data integrity issues. Unauthorized modification of events and occurrences in the calendar. An attacker can alter event timings, potentially causing scheduling conflicts, misinformation, or disruption of planned activities for legitimate users.

* **Vulnerability Rank:** Critical

* **Currently Implemented Mitigations:**
    - Sensitive views and API endpoints are decorated with permission check functions (e.g. via `check_event_permissions` and `check_occurrence_permissions`).
    - The project uses `CHECK_OCCURRENCE_PERM_FUNC` and `CHECK_EVENT_PERM_FUNC` to perform permission checks before modifying occurrences and events in the `_api_move_or_resize_by_code` function.
    - However, these decorators and functions rely on default implementations that only check `user.is_authenticated`.

* **Missing Mitigations:**
    - A robust, fine‑grained authorization check is missing. The system should verify event ownership or privileges (for example, through role‑based or ownership‑based checks) before allowing modifications.
    - Granular permission checks are missing. The project needs to implement authorization logic within `CHECK_OCCURRENCE_PERM_FUNC` and `CHECK_EVENT_PERM_FUNC` to verify if the logged-in user has the right to modify the specific event or occurrence they are targeting. This could involve checking user roles, calendar ownership, or specific event permissions.
    - Input validation and sanitization for parameters like `id`, `event_id`, and `delta` to prevent unexpected behavior or potential injection issues (although less likely due to Django ORM usage).

* **Preconditions:**
    - The attacker must be able to log in to the system (even as a non‑privileged user).
    - A publicly accessible instance of the Django Scheduler application must be running.
    - User authentication must be enabled.
    - Default or misconfigured permission settings are in place, where `CHECK_OCCURRENCE_PERM_FUNC` and `CHECK_EVENT_PERM_FUNC` only check for user authentication and not specific authorization to modify events.

* **Source Code Analysis:**
    1. In **schedule/settings.py**, the default permission function is defined as:
       ```python
       def check_event_permission(ob, user):
           return user.is_authenticated
       ```
       ```python
       if not CHECK_EVENT_PERM_FUNC:
           def check_event_permission(ob, user):
               return user.is_authenticated
           CHECK_EVENT_PERM_FUNC = check_event_permission

       if not CHECK_OCCURRENCE_PERM_FUNC:
           def check_occurrence_permission(ob, user):
               return CHECK_EVENT_PERM_FUNC(ob.event, user)
           CHECK_OCCURRENCE_PERM_FUNC = check_occurrence_permission
       ```
    2. In views (such as in the `_api_move_or_resize_by_code` function in **schedule/views.py** and `_api_move_or_resize_by_code` function in **schedule/views.py**), the permission is checked as follows:
       ```python
       if CHECK_OCCURRENCE_PERM_FUNC(occurrence, user):
           occurrence.save()
       ```
       ```python
       if existed:
           occurrence = Occurrence.objects.get(id=id)
           # ... modification of occurrence ...
           if CHECK_OCCURRENCE_PERM_FUNC(occurrence, user): # Permission check
               occurrence.save()
               response_data["status"] = "OK"
       else:
           event = Event.objects.get(id=event_id)
           # ... modification of event ...
           if CHECK_EVENT_PERM_FUNC(event, user): # Permission check
               event.save()
               # ... update related occurrences ...
               response_data["status"] = "OK"
       ```
       Because the check merely verifies that the user is authenticated, any logged‑in user can trigger changes on any occurrence. The code includes permission check points using `CHECK_OCCURRENCE_PERM_FUNC` and `CHECK_EVENT_PERM_FUNC`. However, the default implementation of these functions only verifies user authentication. If these settings are not overridden to implement proper authorization logic, any authenticated user can bypass the intended access control and modify events or occurrences. The vulnerability lies in the insufficient default permission check logic.

* **Security Test Case:**
    1. Create two user accounts (e.g. “victim” and “attacker”).
    2. Log in as “victim” and create an event using the scheduler.
    3. Log out and then log in as “attacker.”
    4. Use the application’s front‑end or directly send a POST request (for example, via the API endpoint `api_move_or_resize_by_code`) with parameters (such as the victim’s occurrence ID and the appropriate delta) to modify the event’s timing.
    5. Verify that the change is applied, even though “attacker” is not the event’s owner.
    6. **Pre-requisites:**
        - Set up a Django Scheduler application instance with default settings (or without overriding `CHECK_EVENT_PERM_FUNC` and `CHECK_OCCURRENCE_PERM_FUNC`).
        - Create two user accounts: user1 and user2.
        - Log in as user1 and create a calendar named "Test Calendar 1" and an event named "Event 1" on this calendar.
        - Log out and log in as user2.
    7. **Steps:**
        - Using browser developer tools or a tool like `curl`, inspect the network requests when interacting with the calendar (e.g., dragging and dropping "Event 1" in the calendar view to move it). Identify the POST request to `/api/move_or_resize/`.
        - Observe the parameters sent in the POST request, specifically `id` (or `event_id` if it's a new occurrence) and other relevant parameters.
        - As user2, craft a similar POST request to `/api/move_or_resize/`. To modify "Event 1" created by user1, you may need to find the `event_id` for "Event 1". One way to find `event_id` is to use `/api/occurrences` endpoint to list events and their IDs.
        - Set the POST parameters in your crafted request to target "Event 1" (using its `event_id` or `id` if it's a persisted occurrence). Send the request to `/api/move_or_resize/` endpoint while logged in as user2.
    8. **Expected Result:**
        - The request should be successful (HTTP 200 OK and `status: OK` in JSON response).
        - Log in as user1 and navigate to "Test Calendar 1".
        - Verify that "Event 1" has been moved or resized according to the `delta` parameter you sent in the crafted request from user2's account, even though user2 is not supposed to have permission to modify user1's events on "Test Calendar 1" based on typical role-based access control expectations.


### Unrestricted Access to Event Creation via API Endpoint

* **Description:**
    1. An attacker logs in to the application with a valid user account.
    2. The attacker identifies the `api_select_create` API endpoint, used by the calendar to create events by selecting a time range.
    3. The attacker crafts a POST request to `/api/select_create/` with parameters including `start`, `end` (date and time strings), and `calendar_slug`.
    4. The attacker can manipulate the `calendar_slug` parameter to specify any calendar in the application, potentially including calendars they are not authorized to create events on.
    5. If the default permission settings are in place (or misconfigured), the `CHECK_CALENDAR_PERM_FUNC` might only check for user authentication (`user.is_authenticated`) and not verify if the logged-in user has specific rights to add events to the targeted calendar.
    6. The server-side code in `_api_select_create` then proceeds to create the event in the specified calendar based on the provided parameters without proper authorization checks beyond basic authentication.
    7. An event is created in the targeted calendar by the attacker, even if they should not have permission to do so.
    8. Furthermore, when the configuration setting `CALENDAR_VIEW_PERM` is disabled (its default is False), the permission decorator bypasses authentication entirely. This configuration allows both unauthenticated and unauthorized users to create events.

* **Impact:**
    Unauthorized creation of events in any calendar. An attacker can flood calendars with unwanted events, causing clutter, misinformation, or potentially disrupting the intended use of calendars by legitimate users. An attacker or automated bot can flood the calendar with fake events. This can result in data pollution and may disrupt the scheduling functionality.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - The endpoint requires a POST request (via `@require_POST`).
    - It is wrapped by a permission decorator `@check_calendar_permissions`; however, when `CALENDAR_VIEW_PERM` is False the decorator does not enforce authentication.
    - The project uses `@check_calendar_permissions` decorator for the `api_select_create` view, which utilizes `CHECK_CALENDAR_PERM_FUNC` for permission checks.  However, as with the previous vulnerability, the default implementation of `CHECK_CALENDAR_PERM_FUNC` in `schedule/settings.py` only checks for user authentication (`user.is_authenticated`).

* **Missing Mitigations:**
    - Enforce authentication and a proper authorization mechanism on all API endpoints that allow modification or creation of data.
    - Tie event creation to the identity of the authenticated user (for example, by explicitly setting the creator field) and restrict who may create events.
    - Granular permission checks are missing. The project needs to implement authorization logic within `CHECK_CALENDAR_PERM_FUNC` to verify if the logged-in user has the right to add events to the specific calendar they are targeting. This could involve checking user roles, calendar ownership, or specific calendar permissions.
    - Input validation and sanitization for parameters like `start`, `end`, and `calendar_slug` to ensure data integrity and prevent unexpected issues.

* **Preconditions:**
    - The default settings are in place (with `CALENDAR_VIEW_PERM = False`), allowing the API to be used without further access control.
    - A publicly accessible instance of the Django Scheduler application must be running.
    - User authentication must be enabled, or `CALENDAR_VIEW_PERM` is False.
    - Default or misconfigured permission settings are in place, where `CHECK_CALENDAR_PERM_FUNC` only checks for user authentication and not specific authorization to create events in calendars.
    - An attacker must have a valid user account to log in to the application (unless `CALENDAR_VIEW_PERM` is False).

* **Source Code Analysis:**
    1. In **schedule/views.py**, the endpoint is defined as:
       ```python
       @require_POST
       @check_calendar_permissions
       def api_select_create(request):
           start = request.POST.get("start")
           end = request.POST.get("end")
           calendar_slug = request.POST.get("calendar_slug")
           response_data = _api_select_create(start, end, calendar_slug)
           return JsonResponse(response_data)
       ```
    2. The internal function `_api_select_create` parses the start and end times and creates a new event:
       ```python
       Event.objects.create(
           start=start, end=end, title=EVENT_NAME_PLACEHOLDER, calendar=calendar
       )
       ```
    3. Since `CALENDAR_VIEW_PERM` defaults to False, the decorator bypasses authentication, meaning any user can create an event.
    4. **Permission Decorator:** `@check_calendar_permissions` is applied to the `api_select_create` view function. This decorator uses `CHECK_CALENDAR_PERM_FUNC` internally.
    5. **Default Permission Function (File:** `/code/schedule/settings.py` **):**
       ```python
       if not CHECK_CALENDAR_PERM_FUNC:
           def check_calendar_permission(ob, user):
               return user.is_authenticated
           CHECK_CALENDAR_PERM_FUNC = check_calendar_permission
       ```
    6. **Analysis:** The `api_select_create` view is protected by the `@check_calendar_permissions` decorator, which uses `CHECK_CALENDAR_PERM_FUNC`. However, the default `CHECK_CALENDAR_PERM_FUNC` only checks for user authentication. If this setting is not overridden, any authenticated user can call the `api_select_create` API and create events on *any* calendar by manipulating the `calendar_slug` parameter, bypassing intended calendar-level access control for event creation.  When `CALENDAR_VIEW_PERM` is False, the decorator might bypass authentication entirely, allowing unauthenticated users to create events.

* **Security Test Case:**
    1. Without logging in, send a POST request to `/api/select_create/` with valid POST parameters for “start”, “end”, and “calendar_slug.”
    2. Check (via the application interface or directly in the database) that a new event is created with the default placeholder title.
    3. Confirm that the event lacks an owner assignment and that access control was not enforced.
    4. **Pre-requisites:**
        - Set up a Django Scheduler application instance with default settings (or without overriding `CHECK_CALENDAR_PERM_FUNC`).
        - Create two user accounts: user1 and user2.
        - Log in as user1 and create a calendar named "Test Calendar 1".
        - Log in as user2 and create a calendar named "Test Calendar 2".
        - Log out and log in as user1.
    5. **Steps:**
        - Using browser developer tools or a tool like `curl`, inspect the network requests when creating an event by selecting a time range in the calendar (FullCalendar view is suitable for this). Identify the POST request to `/api/select_create/`.
        - Observe the parameters sent in the POST request, specifically `start`, `end`, and `calendar_slug`.
        - As user1, craft a similar POST request to `/api/select_create/`. Modify the `calendar_slug` parameter in your crafted request to be the slug of "Test Calendar 2", which is owned by user2. Send the request to `/api/select_create/` endpoint while logged in as user1.
    6. **Expected Result:**
        - The request should be successful (HTTP 200 OK and `status: OK` in JSON response).
        - Log out and log in as user2.
        - Navigate to "Test Calendar 2".
        - Verify that an event (with the default "Event Name" title or similar) has been created in "Test Calendar 2", even though you were logged in as user1 and should not have permission to create events in user2's calendar "Test Calendar 2" based on typical calendar ownership access control expectations.


### Insufficient Input Validation in API Endpoints Leading to Server Errors

* **Description:**
    Several API endpoints perform direct type conversions and date parsing on user‑supplied parameters without rigorous validation or sanitization. For example, in the `api_move_or_resize_by_code` endpoint the “delta” parameter is converted via:
    ```python
    delta = datetime.timedelta(minutes=int(request.POST.get("delta")))
    ```
    without verifying that it is numeric. Similarly, the `api_occurrences` endpoint uses custom date “convert” functions that assume specific string formats. Malformed inputs may trigger unexpected runtime exceptions.

* **Impact:**
    An attacker may trigger unhandled exceptions that result in HTTP 500 errors. When debug settings are misconfigured in production, such errors might reveal stack traces or internal data structures, thereby leaking potentially useful information for further attacks.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - Some endpoints include basic try/except blocks (especially around date parsing in `api_occurrences`), but these are not comprehensive.
    - The endpoints assume that the input data strictly follows specific formats rather than enforcing them.

* **Missing Mitigations:**
    - Implement robust input validation (for example, using Django forms or serializers) to enforce strict data types and formats before processing.
    - Add comprehensive error handling that catches malformed inputs and returns generic error messages without revealing internal details.

* **Preconditions:**
    The API endpoints are publicly accessible (or accessible to authenticated users) and an attacker can supply arbitrary POST or GET parameters.

* **Source Code Analysis:**
    1. In **schedule/views.py**, the `api_move_or_resize_by_code` endpoint retrieves the “delta” value and immediately converts it:
       ```python
       delta = datetime.timedelta(minutes=int(request.POST.get("delta")))
       ```
       If a non‑numeric string is provided, a `ValueError` will be raised.
    2. In the same file, the `api_occurrences` function uses a nested `convert` function that attempts to parse date strings with fixed formats (`"%Y-%m-%d"` or `"%Y-%m-%dT%H:%M:%S"`). If the data does not match these formats, a `ValueError` is raised.
    3. These instances demonstrate that there is no robust pre‑validation of the inputs before type conversion or date parsing.

* **Security Test Case:**
    1. Use a tool such as curl or Postman to send a POST request to the `/api/move_or_resize/` endpoint with the “delta” parameter set to a non‑numeric value (e.g. “abc”).
    2. Observe whether the application returns an HTTP 500 Internal Server Error and inspect any error details.
    3. Similarly, send a GET request to `/api/occurrences` with deliberately malformed date strings for “start” and “end”.
    4. Verify that improper inputs trigger errors and note whether error messages expose internal details.


### Insufficient Input Validation in Recurrence Rule Parameters Leading to Application Errors

* **Description:**
    The recurrence rule functionality allows for defining event recurrences using a textual parameter string (stored in the `params` field of the Rule model). The method `get_params` in **schedule/models/rules.py** parses this string by splitting it into key‑value pairs and converting each value to an integer or a weekday constant. However, there is no strict validation or whitelisting of the parameter keys or the allowed value ranges. An attacker who can supply or manipulate the recurrence rule (for example, via an event creation API endpoint or through an admin interface) may inject malformed or unexpected parameters. When these parameters are later passed directly to the dateutil.rrule constructor in `Event.get_rrule_object`, they may trigger runtime exceptions.

* **Impact:**
    Triggering a runtime exception in the recurrence rule generation may lead to HTTP 500 errors, resulting in service disruption. If debug settings are enabled, such errors could reveal sensitive internal information (for example, stack traces and internal parameter values). This disrupts scheduling functionality and may aid an attacker in further probing the system.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - In the `get_params` method, the parameter string is split and attempts are made to convert values using a basic helper function (`_weekday_or_number`).
    - There is no explicit validation or enforcement of an allowed set of keys or value formats.

* **Missing Mitigations:**
    - Implement robust input validation for the recurrence rule parameters. Use a strict schema or whitelist that only permits known keys (such as “count”, “bysetpos”, “bymonth”, “bymonthday”, etc.) and validates that the associated values fall within acceptable ranges.
    - Add comprehensive error handling in the recurrence rule generation to catch and log invalid parameters without exposing sensitive error details to the end user.

* **Preconditions:**
    The attacker must be able to supply or modify a recurrence rule’s `params` value (for example, via an unprotected event creation or rule‑editing endpoint) and have that rule used in generating event occurrences (triggering a call to `Event.get_rrule_object`).

* **Source Code Analysis:**
    1. In **schedule/models/rules.py**, the `get_params` method processes the textual `params` field as follows:
       - The method splits the string on semicolons to separate key‑value pairs.
       - Each key‑value pair is further split on a colon; if the split does not yield exactly two elements, the pair is skipped.
       - The value part is split by commas and each token is processed through `_weekday_or_number`, which attempts an integer conversion or maps known weekday abbreviations.
       - No check is made to ensure that the keys are among a defined list of allowed recurrence parameters.
    2. In **schedule/models/events.py**, the recurrence rule is constructed in `get_rrule_object` by retrieving these parameters using:
       ```python
       params = self._event_params()
       return rrule.rrule(frequency, dtstart=dtstart, until=until, **params)
       ```
       Here, any malformed or unexpected key/value in `params` is passed directly to dateutil’s rrule constructor, which may then raise an exception.

* **Security Test Case:**
    1. Through an API endpoint or the admin interface, create a new recurrence rule with the `params` field set to an invalid string (for example, `"invalid_key:non_numeric"`).
    2. Associate this rule with an event so that when `Event.get_rrule_object()` is called it uses the invalid rule.
    3. Access an API endpoint or view that triggers the generation of event occurrences (for example, by calling `get_occurrence()` or `get_occurrences()` on the event).
    4. Verify that this input results in an HTTP 500 error (or another unhandled exception) and that the response reveals internal error details, indicating that proper input validation and error handling are missing.