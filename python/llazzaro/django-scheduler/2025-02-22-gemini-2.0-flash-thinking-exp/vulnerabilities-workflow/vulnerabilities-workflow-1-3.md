### Vulnerability List

* Vulnerability Name: Missing Authorization in `api_move_or_resize_by_code` API

* Description:
    1. An attacker logs in to the application with a valid user account.
    2. The attacker identifies the `api_move_or_resize_by_code` API endpoint, used by the calendar to move or resize events.
    3. The attacker crafts a POST request to `/api/move_or_resize/` with parameters including `id` (occurrence ID or event ID), `existed` (boolean indicating if it's a persisted occurrence), `delta` (time difference in minutes), `resize` (boolean indicating resize operation), and `event_id` (event ID).
    4. The attacker can modify the parameters such as `id` or `event_id` to target events or occurrences belonging to other users or calendars, even without explicit authorization to do so on those specific events or calendars.
    5. If the default permission settings are in place (or misconfigured), the `CHECK_OCCURRENCE_PERM_FUNC` or `CHECK_EVENT_PERM_FUNC` might only check for user authentication (`user.is_authenticated`) and not verify if the logged-in user has specific rights to modify the targeted event or occurrence.
    6. The server-side code in `_api_move_or_resize_by_code` then proceeds to modify the event or occurrence based on the provided parameters without proper authorization checks beyond basic authentication.
    7. The event or occurrence is moved or resized by the attacker, potentially causing disruption or unauthorized modification of calendar data.

* Impact:
    Unauthorized modification of events and occurrences in the calendar. An attacker can alter event timings, potentially causing scheduling conflicts, misinformation, or disruption of planned activities for legitimate users.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    The project uses `CHECK_OCCURRENCE_PERM_FUNC` and `CHECK_EVENT_PERM_FUNC` to perform permission checks before modifying occurrences and events in the `_api_move_or_resize_by_code` function. However, the default implementation of these functions in `schedule/settings.py` only verifies if a user is authenticated (`user.is_authenticated`).

* Missing Mitigations:
    - Granular permission checks are missing. The project needs to implement authorization logic within `CHECK_OCCURRENCE_PERM_FUNC` and `CHECK_EVENT_PERM_FUNC` to verify if the logged-in user has the right to modify the specific event or occurrence they are targeting. This could involve checking user roles, calendar ownership, or specific event permissions.
    - Input validation and sanitization for parameters like `id`, `event_id`, and `delta` to prevent unexpected behavior or potential injection issues (although less likely due to Django ORM usage).

* Preconditions:
    - A publicly accessible instance of the Django Scheduler application must be running.
    - User authentication must be enabled.
    - Default or misconfigured permission settings are in place, where `CHECK_OCCURRENCE_PERM_FUNC` and `CHECK_EVENT_PERM_FUNC` only check for user authentication and not specific authorization to modify events.
    - An attacker must have a valid user account to log in to the application.

* Source Code Analysis:
    1. **File:** `/code/schedule/views.py`
    2. **Function:** `_api_move_or_resize_by_code(user, id, existed, delta, resize, event_id)`
    3. **Permission Check:**
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
    4. **Default Permission Functions (File:** `/code/schedule/settings.py` **):**
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
    5. **Analysis:** The code includes permission check points using `CHECK_OCCURRENCE_PERM_FUNC` and `CHECK_EVENT_PERM_FUNC`. However, the default implementation of these functions only verifies user authentication. If these settings are not overridden to implement proper authorization logic, any authenticated user can bypass the intended access control and modify events or occurrences. The vulnerability lies in the insufficient default permission check logic.

* Security Test Case:
    1. **Pre-requisites:**
        - Set up a Django Scheduler application instance with default settings (or without overriding `CHECK_EVENT_PERM_FUNC` and `CHECK_OCCURRENCE_PERM_FUNC`).
        - Create two user accounts: user1 and user2.
        - Log in as user1 and create a calendar named "Test Calendar 1" and an event named "Event 1" on this calendar.
        - Log out and log in as user2.
    2. **Steps:**
        - Using browser developer tools or a tool like `curl`, inspect the network requests when interacting with the calendar (e.g., dragging and dropping "Event 1" in the calendar view to move it). Identify the POST request to `/api/move_or_resize/`.
        - Observe the parameters sent in the POST request, specifically `id` (or `event_id` if it's a new occurrence) and other relevant parameters.
        - As user2, craft a similar POST request to `/api/move_or_resize/`. To modify "Event 1" created by user1, you may need to find the `event_id` for "Event 1". One way to find `event_id` is to use `/api/occurrences` endpoint to list events and their IDs.
        - Set the POST parameters in your crafted request to target "Event 1" (using its `event_id` or `id` if it's a persisted occurrence). Send the request to `/api/move_or_resize/` endpoint while logged in as user2.
    3. **Expected Result:**
        - The request should be successful (HTTP 200 OK and `status: OK` in JSON response).
        - Log in as user1 and navigate to "Test Calendar 1".
        - Verify that "Event 1" has been moved or resized according to the `delta` parameter you sent in the crafted request from user2's account, even though user2 is not supposed to have permission to modify user1's events on "Test Calendar 1" based on typical role-based access control expectations.

---

* Vulnerability Name: Missing Authorization in `api_select_create` API

* Description:
    1. An attacker logs in to the application with a valid user account.
    2. The attacker identifies the `api_select_create` API endpoint, used by the calendar to create events by selecting a time range.
    3. The attacker crafts a POST request to `/api/select_create/` with parameters including `start`, `end` (date and time strings), and `calendar_slug`.
    4. The attacker can manipulate the `calendar_slug` parameter to specify any calendar in the application, potentially including calendars they are not authorized to create events on.
    5. If the default permission settings are in place (or misconfigured), the `CHECK_CALENDAR_PERM_FUNC` might only check for user authentication (`user.is_authenticated`) and not verify if the logged-in user has specific rights to add events to the targeted calendar.
    6. The server-side code in `_api_select_create` then proceeds to create the event in the specified calendar based on the provided parameters without proper authorization checks beyond basic authentication.
    7. An event is created in the targeted calendar by the attacker, even if they should not have permission to do so.

* Impact:
    Unauthorized creation of events in any calendar. An attacker can flood calendars with unwanted events, causing clutter, misinformation, or potentially disrupting the intended use of calendars by legitimate users.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    The project uses `@check_calendar_permissions` decorator for the `api_select_create` view, which utilizes `CHECK_CALENDAR_PERM_FUNC` for permission checks.  However, as with the previous vulnerability, the default implementation of `CHECK_CALENDAR_PERM_FUNC` in `schedule/settings.py` only checks for user authentication (`user.is_authenticated`).

* Missing Mitigations:
    - Granular permission checks are missing. The project needs to implement authorization logic within `CHECK_CALENDAR_PERM_FUNC` to verify if the logged-in user has the right to add events to the specific calendar they are targeting. This could involve checking user roles, calendar ownership, or specific calendar permissions.
    - Input validation and sanitization for parameters like `start`, `end`, and `calendar_slug` to ensure data integrity and prevent unexpected issues.

* Preconditions:
    - A publicly accessible instance of the Django Scheduler application must be running.
    - User authentication must be enabled.
    - Default or misconfigured permission settings are in place, where `CHECK_CALENDAR_PERM_FUNC` only checks for user authentication and not specific authorization to create events in calendars.
    - An attacker must have a valid user account to log in to the application.

* Source Code Analysis:
    1. **File:** `/code/schedule/views.py`
    2. **Function:** `_api_select_create(start, end, calendar_slug)` (called by `api_select_create` view)
    3. **Permission Decorator:** `@check_calendar_permissions` is applied to the `api_select_create` view function. This decorator uses `CHECK_CALENDAR_PERM_FUNC` internally.
    4. **Default Permission Function (File:** `/code/schedule/settings.py` **):**
       ```python
       if not CHECK_CALENDAR_PERM_FUNC:
           def check_calendar_permission(ob, user):
               return user.is_authenticated
           CHECK_CALENDAR_PERM_FUNC = check_calendar_permission
       ```
    5. **Analysis:** The `api_select_create` view is protected by the `@check_calendar_permissions` decorator, which uses `CHECK_CALENDAR_PERM_FUNC`. However, the default `CHECK_CALENDAR_PERM_FUNC` only checks for user authentication. If this setting is not overridden, any authenticated user can call the `api_select_create` API and create events on *any* calendar by manipulating the `calendar_slug` parameter, bypassing intended calendar-level access control for event creation.

* Security Test Case:
    1. **Pre-requisites:**
        - Set up a Django Scheduler application instance with default settings (or without overriding `CHECK_CALENDAR_PERM_FUNC`).
        - Create two user accounts: user1 and user2.
        - Log in as user1 and create a calendar named "Test Calendar 1".
        - Log in as user2 and create a calendar named "Test Calendar 2".
        - Log out and log in as user1.
    2. **Steps:**
        - Using browser developer tools or a tool like `curl`, inspect the network requests when creating an event by selecting a time range in the calendar (FullCalendar view is suitable for this). Identify the POST request to `/api/select_create/`.
        - Observe the parameters sent in the POST request, specifically `start`, `end`, and `calendar_slug`.
        - As user1, craft a similar POST request to `/api/select_create/`. Modify the `calendar_slug` parameter in your crafted request to be the slug of "Test Calendar 2", which is owned by user2. Send the request to `/api/select_create/` endpoint while logged in as user1.
    3. **Expected Result:**
        - The request should be successful (HTTP 200 OK and `status: OK` in JSON response).
        - Log out and log in as user2.
        - Navigate to "Test Calendar 2".
        - Verify that an event (with the default "Event Name" title or similar) has been created in "Test Calendar 2", even though you were logged in as user1 and should not have permission to create events in user2's calendar "Test Calendar 2" based on typical calendar ownership access control expectations.