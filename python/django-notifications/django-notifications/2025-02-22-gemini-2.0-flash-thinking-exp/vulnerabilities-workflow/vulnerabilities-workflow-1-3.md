- Vulnerability Name: Insecure Direct Object Reference in Notification Deletion and Read/Unread Marks

- Description:
An attacker can delete or mark as read/unread any notification belonging to any user by guessing or iterating through notification IDs. The application uses sequential IDs for notifications and lacks proper authorization checks to ensure that only the recipient of a notification can modify its status or delete it. An attacker can simply change the `slug` parameter in the URL to target other users' notifications.

Steps to trigger:
1. Log in to the application as user A.
2. Observe the URL when deleting or marking a notification as read/unread. The URL will contain a slug, which is derived from the notification ID. For example: `/inbox/notifications/delete/123/` or `/inbox/notifications/mark-as-read/123/`.
3. Log out and log in as user B.
4. As user B, attempt to access user A's notifications by using the same or incremented/decremented slug (notification ID) observed in step 2 in the delete or mark as read/unread URLs. For example, if user A's notification ID was 123, user B can try `/inbox/notifications/delete/123/`, `/inbox/notifications/mark-as-read/123/`, or `/inbox/notifications/mark-as-unread/123/`.
5. If the notification ID exists and belongs to any user, the application will process the request without verifying if the currently logged-in user is the actual recipient of the notification.

- Impact:
Unauthorized modification or deletion of notifications. An attacker can read, mark as read, mark as unread, or delete notifications belonging to other users. This can lead to information disclosure (reading notifications), disruption of notification functionality for legitimate users (deleting notifications), and confusion or manipulation of user activity records.

- Vulnerability Rank: High

- Currently implemented mitigations:
None. The code checks if the notification exists and belongs to *a* recipient, but not if it belongs to the *current* logged-in user in the `delete`, `mark_as_read`, and `mark_as_unread` views.

- Missing mitigations:
Implement proper authorization checks in the `delete`, `mark_as_read`, and `mark_as_unread` views to ensure that the logged-in user is the recipient of the notification being modified or deleted. This can be achieved by filtering the notification queryset to only include notifications where `recipient=request.user` before retrieving the notification using `get_object_or_404`.

- Preconditions:
An attacker must be a logged-in user of the application. The application must have notifications created for multiple users. Notification IDs must be somewhat predictable or enumerable (sequential IDs are easily guessable).

- Source code analysis:

```python
# File: /code/notifications/views.py

@login_required
def mark_as_read(request, slug=None):
    notification_id = slug2id(slug)

    # Vulnerable code: No check to ensure notification belongs to request.user
    notification = get_object_or_404(
        Notification, recipient=request.user, id=notification_id) # recipient=request.user is present but doesn't prevent IDOR
    notification.mark_as_read()
    # ...

@login_required
def mark_as_unread(request, slug=None):
    notification_id = slug2id(slug)

    # Vulnerable code: No check to ensure notification belongs to request.user
    notification = get_object_or_404(
        Notification, recipient=request.user, id=notification_id) # recipient=request.user is present but doesn't prevent IDOR
    notification.mark_as_unread()
    # ...


@login_required
def delete(request, slug=None):
    notification_id = slug2id(slug)

    # Vulnerable code: No check to ensure notification belongs to request.user
    notification = get_object_or_404(
        Notification, recipient=request.user, id=notification_id) # recipient=request.user is present but doesn't prevent IDOR

    if notification_settings.get_config()['SOFT_DELETE']:
        notification.deleted = True
        notification.save()
    else:
        notification.delete()
    # ...
```

In the `mark_as_read`, `mark_as_unread`, and `delete` views, the `get_object_or_404` function is used to retrieve a notification. While it includes `recipient=request.user` in the query, this is insufficient to prevent IDOR. The vulnerability lies in the fact that `get_object_or_404` will return *any* notification that matches the `id` and *any* recipient being `request.user`. It does not guarantee that the notification with the given `id` actually *belongs* to `request.user`.  If a notification with a guessed ID exists for *any* user, and the logged-in user is *any* recipient (which is always true in this flawed logic), the notification will be retrieved and the action performed. The intended check was likely to verify *at least one* notification exists for the current user, but it fails to enforce ownership of the specific notification being targeted by ID.

To visualize the vulnerability, consider two users, User A and User B.
1. User A has notification with ID 123.
2. User B can access `/inbox/notifications/mark-as-read/123/`.
3. The query executed will be `SELECT * FROM notifications WHERE recipient = UserB AND id = 123`.
4. This query is logically flawed. It should be `SELECT * FROM notifications WHERE recipient = UserB AND id = 123 AND recipient = UserB` (or effectively, just `SELECT * FROM notifications WHERE recipient = UserB AND id = 123` but ensuring the notification with ID 123 *actually belongs* to User B).
5. Because the condition `recipient = request.user` is always true for *some* recipient (the currently logged in user), and the ID is simply checked for existence, any notification ID can be targeted as long as a user is logged in.
6. The correct check should be to verify if `Notification.objects.filter(recipient=request.user, id=notification_id).exists()` *before* attempting to retrieve and modify the notification. However, the current code uses `get_object_or_404` which directly retrieves and operates on the notification based on the flawed query.

- Security test case:

1. Create two test users, user1 and user2.
2. Log in as user1.
3. Create a notification for user1 (e.g., by triggering an action that sends a notification to user1). Note the slug (notification ID) of this notification from the URL after performing an action like deleting or marking as read/unread in the UI, or by inspecting the notification list in the UI's source code if IDs are exposed there. Let's say the slug is '100'.
4. Log out of user1 and log in as user2.
5. As user2, construct a URL to delete the notification of user1 using the slug '100' obtained in step 3: `/inbox/notifications/delete/100/`.
6. Send a GET request to this URL using user2's session.
7. Log out of user2 and log back in as user1.
8. Check if the notification created for user1 in step 3 has been deleted. If it is deleted, then user2 was able to delete user1's notification, confirming the IDOR vulnerability.
9. Repeat steps 4-8 for `mark-as-read` and `mark-as-unread` URLs: `/inbox/notifications/mark-as-read/100/` and `/inbox/notifications/mark-as-unread/100/`, and verify if user2 can modify the read status of user1's notification.