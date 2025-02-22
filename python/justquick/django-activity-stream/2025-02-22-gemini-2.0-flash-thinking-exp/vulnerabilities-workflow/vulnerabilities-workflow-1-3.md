### Vulnerability List:

- Insecure Direct Object Reference (IDOR) in Follow/Unfollow Functionality

#### Vulnerability Name:
Insecure Direct Object Reference (IDOR) in Follow/Unfollow Functionality

#### Description:
The `follow_unfollow` view in `actstream/views.py` allows users to create or delete "follow" relationships between a user and an arbitrary object. This view uses `content_type_id` and `object_id` from the URL to identify the object to be followed/unfollowed. However, it lacks proper authorization checks to ensure that the user initiating the follow/unfollow action is authorized to interact with the target object in this manner. An attacker could potentially manipulate the `content_type_id` and `object_id` parameters to follow or unfollow objects they should not have access to, leading to unauthorized access to activity streams related to those objects.

**Step-by-step trigger:**
1. An attacker identifies a valid `content_type_id` and `object_id` of an object they are *not* supposed to follow (e.g., a private user profile, a restricted group, etc.). Let's assume this object is of ContentType 'testapp.Player' with pk=10.
2. The attacker, logged in as a regular user, crafts a request to the `/follow/<content_type_id>/<object_id>/` endpoint, replacing `<content_type_id>` with the ContentType ID of 'testapp.Player' and `<object_id>` with '10'. For example, if ContentType ID for 'testapp.Player' is 'X', the attacker would access `/follow/X/10/`.
3. The `follow_unfollow` view, without proper authorization checks, will create a "follow" relationship between the attacker's user and the 'testapp.Player' object with pk=10.
4. The attacker can now access activity streams related to the followed object, potentially gaining unauthorized insights into activities associated with that object.
5. Similarly, an attacker could use the `/unfollow/<content_type_id>/<object_id>/` endpoint to unfollow objects, even if they were not initially authorized to establish the follow relationship, or if removing the follow relationship has unintended consequences.

#### Impact:
- **Information Disclosure:** An attacker can gain unauthorized access to activity streams of objects they are not intended to follow. This can reveal sensitive information about the followed objects, their activities, and interactions with other users or objects within the application.
- **Data Manipulation (Indirect):** While not direct data manipulation of the target object, the ability to follow/unfollow objects without authorization can disrupt the intended activity stream behavior for users and potentially lead to confusion or misrepresentation of user activity.

#### Vulnerability Rank:
High

#### Currently Implemented Mitigations:
- **Login Required Decorator:** The `follow_unfollow` view is protected by the `@login_required` decorator, ensuring that only authenticated users can access the functionality. However, this only verifies authentication, not authorization to follow/unfollow *specific* objects.
- **CSRF Protection:** The `@csrf_exempt` decorator is used because the view is intended to be used with POST requests (though GET is also possible in the current code). CSRF protection is generally enabled by Django middleware. This protects against CSRF attacks but does not mitigate IDOR.

#### Missing Mitigations:
- **Authorization Checks:** The most critical missing mitigation is authorization checks within the `follow_unfollow` view. Before creating or deleting a follow relationship, the application should verify if the logged-in user has the necessary permissions to follow or unfollow the specified object. This check should be context-aware and depend on the application's specific access control requirements. For instance, it might involve checking object-level permissions or enforcing business logic rules related to following/unfollowing.
- **Input Validation and Sanitization:** While `get_object_or_404` provides basic validation by ensuring the object exists, more robust input validation and sanitization could be beneficial. However, authorization is the primary missing mitigation in this case.

#### Preconditions:
- The application must have publicly accessible endpoints for following and unfollowing objects, which are configured by default in `actstream/urls.py`.
- An attacker must be a registered and logged-in user of the application.
- The attacker needs to know or guess valid `content_type_id` and `object_id` values. ContentType IDs are usually sequential integers and can be easily discovered. Object IDs can also be discovered or brute-forced depending on the application.

#### Source Code Analysis:
```python
# /code/actstream/views.py
from django.shortcuts import get_object_or_404, render
from django.http import HttpResponseRedirect, HttpResponse

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.contenttypes.models import ContentType
from django.views.decorators.csrf import csrf_exempt

from actstream import actions, models

USER_MODEL = get_user_model()
username_field = getattr(get_user_model(), 'USERNAME_FIELD', 'username')


def respond(request, code):
    """
    Responds to the request with the given response code.
    If ``next`` is in the form, it will redirect instead.
    """
    redirect = request.GET.get('next', request.POST.get('next'))
    if redirect:
        return HttpResponseRedirect(redirect)
    return type('Response%d' % code, (HttpResponse, ), {'status_code': code})()


@login_required
@csrf_exempt
def follow_unfollow(request, content_type_id, object_id, flag=None, do_follow=True, actor_only=True):
    """
    Creates or deletes the follow relationship between ``request.user`` and the
    actor defined by ``content_type_id``, ``object_id``.
    """
    ctype = get_object_or_404(ContentType, pk=content_type_id)
    instance = get_object_or_404(ctype.model_class(), pk=object_id)

    # If flag was omitted in url, None will pass to flag keyword argument
    flag = flag or ''

    if do_follow:
        actions.follow(request.user, instance, actor_only=actor_only, flag=flag) # [1]
        return respond(request, 201)   # CREATED

    actions.unfollow(request.user, instance, flag=flag) # [2]
    return respond(request, 204)   # NO CONTENT
```
**Code Walkthrough:**
1. The `follow_unfollow` view is decorated with `@login_required`, which ensures that only authenticated users can access this view.
2. It retrieves `content_type_id` and `object_id` from the URL parameters.
3. `get_object_or_404(ContentType, pk=content_type_id)` fetches the ContentType based on the provided ID. This ensures that the `content_type_id` is valid and exists in the database.
4. `get_object_or_404(ctype.model_class(), pk=object_id)` fetches the actual object instance using the retrieved ContentType and the provided `object_id`. This also validates that `object_id` exists for the given ContentType.
5. If `do_follow` is True (default for `/follow/` URLs), it calls `actions.follow(request.user, instance, ...)` [1] to create a follow relationship.
6. If `do_follow` is False (for `/unfollow/` URLs), it calls `actions.unfollow(request.user, instance, ...)` [2] to delete a follow relationship.
7. **Crucially, there are no authorization checks before calling `actions.follow` or `actions.unfollow`.** The view simply proceeds to create or delete the follow relationship as long as the ContentType and object exist.

```python
# /code/actstream/actions.py
from django.apps import apps
from django.utils.translation import gettext_lazy as _
from django.utils.timezone import now
from django.contrib.contenttypes.models import ContentType

from actstream import settings
from actstream.signals import action
from actstream.registry import check


def follow(user, obj, send_action=True, actor_only=True, flag='', **kwargs):
    """ ... """
    check(obj) # [3]
    instance, created = apps.get_model('actstream', 'follow').objects.get_or_create( # [4]
        user=user, object_id=obj.pk, flag=flag,
        content_type=ContentType.objects.get_for_model(obj),
        actor_only=actor_only
    )
    if send_action and created:
        if not flag:
            action.send(user, verb=_('started following'), target=obj, **kwargs)
        else:
            action.send(user, verb=_('started %s' % flag), target=obj, **kwargs)
    return instance


def unfollow(user, obj, send_action=False, flag=''):
    """ ... """
    check(obj) # [5]
    qs = apps.get_model('actstream', 'follow').objects.filter( # [6]
        user=user, object_id=obj.pk,
        content_type=ContentType.objects.get_for_model(obj)
    )

    if flag:
        qs = qs.filter(flag=flag)
    qs.delete()

    if send_action:
        if not flag:
            action.send(user, verb=_('stopped following'), target=obj)
        else:
            action.send(user, verb=_('stopped %s' % flag), target=obj)

```
**Code Walkthrough (actions.py):**
- Both `actions.follow` and `actions.unfollow` functions perform a `check(obj)` [3, 5], which verifies if the model of the object is registered with `actstream`. This is not an authorization check.
- `actions.follow` uses `get_or_create` [4] to create a `Follow` object.
- `actions.unfollow` uses `filter(...).delete()` [6] to remove `Follow` objects.
- **Neither `actions.follow` nor `actions.unfollow` implement any authorization checks.** They operate solely based on the provided user and object, assuming the caller has already performed necessary permission checks.

**Visualization:**

```mermaid
graph LR
    A[User] --> B{/follow/{content_type_id}/{object_id}/};
    B --> C[follow_unfollow View];
    C --> D{get_object_or_404 (ContentType)};
    D --> E{get_object_or_404 (Model)};
    E --> F{actions.follow()};
    F --> G[Create Follow Object];
    G --> H[Response 201];
    C -- No Authorization Check --> F;
    B -- Manipulated content_type_id/object_id --> C;
```

#### Security Test Case:
**Pre-requisites:**
- Ensure the test application includes the 'actstream' app in `INSTALLED_APPS` and has the `actstream.urls` included in its URL configuration.
- Create a model in the test application, e.g., 'testapp.Player', and register it with actstream in `testapp/apps.py` ready() method.
- Create a few instances of 'testapp.Player' objects in the database (e.g., Player.objects.create() for a few players).
- Create two test users: 'attacker' and 'victim'.

**Steps:**
1. Log in to the test application as the 'attacker' user.
2. Identify the ContentType ID for 'testapp.Player'. This can be found by inspecting the 'django_content_type' table in the database or by accessing `/admin/contenttypes/contenttype/` in the admin interface. Let's assume it is 'X'.
3. Identify the object ID of a 'testapp.Player' instance that the 'attacker' user should *not* be able to follow directly. Let's assume there is a 'testapp.Player' object with pk=1, representing a "private" player profile.
4. Craft a GET request to the follow URL using the identified ContentType ID and object ID: `/follow/X/1/`. You can use a browser or tools like `curl` or `Postman`.
5. Send the request to the application.
6. Verify the HTTP response status code is 201 (Created), indicating successful follow action.
7. Log in to the Django admin panel as a superuser.
8. Navigate to the Actstream Follows section in the admin panel (`/admin/actstream/follow/`).
9. Search for a Follow object where:
    - User is 'attacker'
    - Content Type is 'testapp | player'
    - Object ID is '1'
10. Verify that such a Follow object exists. This confirms that the 'attacker' user has successfully followed the 'testapp.Player' object with pk=1, even without explicit authorization to do so.
11. (Optional) Access the activity stream of the 'attacker' user (e.g., `/feed/`) and confirm that actions related to the followed 'testapp.Player' object might now be visible (depending on action types and privacy settings, if any, in the test app).
12. Repeat steps with `/unfollow/X/1/` and verify response code 204 and absence of the Follow object in the admin panel to test unauthorized unfollowing.

This test case demonstrates that a logged-in attacker can successfully follow and unfollow arbitrary 'testapp.Player' objects by manipulating URL parameters, confirming the IDOR vulnerability in the follow/unfollow functionality due to missing authorization checks.