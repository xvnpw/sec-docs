### Vulnerability List

- Vulnerability name: CSRF vulnerability in follow/unfollow functionality
- Description:
    - An attacker can exploit the lack of CSRF protection in the `follow_unfollow` view to perform unauthorized follow or unfollow actions on behalf of a logged-in user.
    - Step 1: Attacker crafts a malicious web page containing a form that automatically submits a POST request to the `/follow/` or `/unfollow/` endpoint of the application. This form will target a specific content type and object ID to be followed or unfollowed. The form will not include a valid CSRF token.
    - Step 2: Attacker tricks a logged-in user into visiting this malicious web page (e.g., through phishing, social engineering, or embedding the form in a compromised website).
    - Step 3: When the user visits the page, the malicious form automatically submits the POST request to the application in the user's session.
    - Step 4: Due to the `@csrf_exempt` decorator on the `follow_unfollow` view, the application does not validate the CSRF token in the request.
    - Step 5: The application processes the request, leading to an unintended follow or unfollow action being performed by the logged-in user without their explicit consent or knowledge.
- Impact:
    - An attacker can arbitrarily manipulate a user's follow list.
    - This can be exploited to:
        - Force users to follow malicious actors, leading to spam or disinformation in their activity streams.
        - Force users to unfollow legitimate actors, disrupting their intended activity stream and potentially causing them to miss important updates.
- Vulnerability rank: high
- Currently implemented mitigations:
    - None. The `@csrf_exempt` decorator in `actstream/views.py` explicitly disables CSRF protection for the `follow_unfollow` view.
- Missing mitigations:
    - CSRF protection should be enabled for the `follow_unfollow` view.
    - Remove the `@csrf_exempt` decorator from the `follow_unfollow` view in `actstream/views.py`.
    - Ensure that the view correctly handles CSRF tokens, either by using Django's `csrf_protect` decorator or by ensuring that templates used for these actions include the `{% csrf_token %}` tag in forms.
- Preconditions:
    - The attacker requires a logged-in user to visit a malicious webpage or trigger a malicious request.
    - The attacker needs to know the `content_type_id` and `object_id` of the object to be followed or unfollowed. This information can often be easily obtained or guessed.
- Source code analysis:
    - File: `/code/actstream/views.py`
    ```python
    from django.views.decorators.csrf import csrf_exempt
    from django.contrib.auth.decorators import login_required

    @login_required
    @csrf_exempt # Vulnerability: CSRF protection is disabled
    def follow_unfollow(request, content_type_id, object_id, flag=None, do_follow=True, actor_only=True):
        """
        Creates or deletes the follow relationship between ``request.user`` and the
        actor defined by ``content_type_id``, ``object_id``.
        """
        # ... function logic ...
    ```
    - The `@csrf_exempt` decorator, located directly above the `follow_unfollow` function definition, explicitly disables Django's built-in CSRF protection for this view. This means that requests to this view are not checked for a valid CSRF token, making it susceptible to CSRF attacks.
- Security test case:
    - Step 1: Log in to the application as a test user.
    - Step 2: Identify the `content_type_id` for 'User' and the `object_id` of another user (e.g., user with username 'Two'). You can find `content_type_id` by inspecting the database table `django_content_type` or by accessing admin panel. Let's assume `content_type_id` for 'User' is 'X' and `object_id` for 'Two' is 'Y'.
    - Step 3: Create an HTML file (e.g., `csrf_test.html`) with the following content:
    ```html
    <html>
    <body>
        <form action="/follow/X/Y/" method="POST" id="csrf-test-form">
            <input type="hidden" name="next" value="/"/>
            <input type="submit" value="Follow User Two" />
        </form>
        <script>
            document.getElementById('csrf-test-form').submit();
        </script>
    </body>
    </html>
    ```
    - Step 4: Serve this HTML file via a simple HTTP server or upload it to a publicly accessible web hosting.
    - Step 5: As the logged-in test user, access the URL of the `csrf_test.html` file in your browser.
    - Step 6: Observe the application's behavior. After accessing the page, navigate to your user profile or activity stream within the application and verify if you are now following user 'Two'.
    - Expected result: You will be successfully following user 'Two' even though the form submission did not include a CSRF token. This confirms the CSRF vulnerability in the `follow_unfollow` view.