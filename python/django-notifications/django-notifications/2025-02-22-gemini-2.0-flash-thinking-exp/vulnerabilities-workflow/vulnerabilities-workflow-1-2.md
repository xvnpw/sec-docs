- **Vulnerability Name:** Insecure Global Cache Key for Unread Notification Count

- **Description:**
  - The project’s template tag for displaying live notification counts uses a fixed cache key.
  - In the file `notifications/templatetags/notifications_tags.py`, the function `get_cached_notification_unread_count(user)` calls:
    ```python
    cache.get_or_set(
        'cache_notification_unread_count',
        user.notifications.unread().count,
        settings.get_config()['CACHE_TIMEOUT']
    )
    ```
    without incorporating a user-specific identifier.
  - Because the same key (`cache_notification_unread_count`) is used regardless of which user is making the request, the first computed unread count is stored and then shared across all subsequent calls.
  - An external attacker (or any authenticated user) can thus trigger or observe a notification count calculated for another user, leading to leakage of internal state information and data confusion.

- **Impact:**
  - Users may see an unread notifications count that does not belong to them.
  - Cross–user leakage of notification metadata (the number of unread notifications) can occur.
  - This behavior undermines user data integrity and may indirectly provide attackers with clues on other users’ activity within the application.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - The code makes use of Django’s caching mechanism with the `cache.get_or_set` method. However, the key itself is hard-coded and does not include any user-specific data.
  - There is no runtime check that rebinds the cached value to each authenticated user.

- **Missing Mitigations:**
  - The cache key should incorporate a unique attribute from the user (for example, the user’s primary key) so that the unread count is stored and retrieved separately for every user.
  - A proper key format might be:  
    `"cache_notification_unread_count_{user.id}"`  
    which would ensure that each user’s unread count is cached independently.

- **Preconditions:**
  - The attacker must have an account (i.e. be authenticated) on the publicly available instance of the application.
  - The attacker needs to trigger the loading of pages that use the `{% live_notify_badge %}` tag so that the unread notification count is served from the cache.
  - Because all logged‐in users share the same cache key, the victim’s (or another user’s) notification count can leak into the attacker’s view under certain conditions.

- **Source Code Analysis:**
  - In `notifications/templatetags/notifications_tags.py` the function is defined as follows:
    ```python
    def get_cached_notification_unread_count(user):
        return cache.get_or_set(
            'cache_notification_unread_count',  # fixed, global key
            user.notifications.unread().count,
            settings.get_config()['CACHE_TIMEOUT']
        )
    ```
  - The cache key is a constant string (`'cache_notification_unread_count'`) rather than being parameterized with user information.
  - When User A’s page calls this function, the unread count for User A is computed and stored under that key.
  - Later, when User B (or any other authenticated user) loads a page that calls the same function, the cached value is returned—even though it originates from User A’s data.
  - This mis-caching causes data from one user session to contaminate another session, leading to both incorrect UI behavior and possible information leakage.

- **Security Test Case:**
  - **Step 1:** Log in as User A on the publicly available instance.
    - Navigate to a page that includes the live notification badge (e.g. by using `{% live_notify_badge %}`).
    - Note the unread count displayed (e.g. there are 5 unread notifications for User A).
  - **Step 2:** Log out User A and then log in as a different user, User B.
  - **Step 3:** Visit the same page on which the notification badge is rendered.
    - Observe that the badge unexpectedly displays the unread count of 5 (or the value determined from User A’s session) instead of User B’s correct unread count.
  - **Step 4:** Repeat the test with additional users.
    - The persistence of the same (wrong) unread count value confirms that the cache key is global and not user-specific.
  - **Step 5:** Document the discrepancy between the actual unread notifications (as queried directly from the database) and the value returned via the cached function.