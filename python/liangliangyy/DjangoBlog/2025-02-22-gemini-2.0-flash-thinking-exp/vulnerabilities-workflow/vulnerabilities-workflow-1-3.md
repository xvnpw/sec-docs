- Vulnerability name: OAuth Account Takeover via Email Binding
- Description:
    1. An attacker initiates an OAuth login (e.g., using GitHub, Google, QQ, Weibo, Facebook).
    2. If the OAuth provider does not return an email address for the user, or if the email is not verified, the application prompts the user to provide an email address to associate with their account.
    3. An attacker can enter any email address during this step, even one that does not belong to them.
    4. If the attacker enters an email address belonging to another user already registered on the DjangoBlog platform (either via standard registration or another OAuth provider), the OAuth account will be linked to the existing user account associated with that email address.
    5. The legitimate user's account is then effectively taken over by the attacker through the newly linked OAuth account. The attacker can log in using the OAuth provider and access the legitimate user's account.

- Impact:
    - Account takeover: An attacker can gain complete control of another user's account on the DjangoBlog platform.
    - Data breach: The attacker can access and potentially modify or delete the legitimate user's blog posts, settings, and personal information.
    - Reputation damage: If the attacker misuses the compromised account, it can damage the reputation of both the user and the DjangoBlog platform.

- Vulnerability rank: Critical

- Currently implemented mitigations:
    - None. The code in `oauth/views.py` allows binding any email address provided by the user during the OAuth email requirement step without proper verification against existing accounts or ownership validation.

- Missing mitigations:
    - Email ownership verification: When a user provides an email address during the OAuth email requirement step, the system should verify if the email is already associated with an existing account.
    - Account linking conflict resolution: If the email is already associated with an existing account, the system should prevent automatic linking and provide a mechanism for the user to prove ownership of the existing account or choose a different email.
    - Email verification:  After the user provides an email, a verification email should be sent to the provided address, requiring the user to click a link to confirm ownership before the email is bound to the OAuth account.

- Preconditions:
    - The target user must have an account on the DjangoBlog platform associated with an email address.
    - The attacker must initiate an OAuth login using a provider that does not automatically provide or verify the user's email address during the OAuth flow, leading to the "require email" step in DjangoBlog.

- Source code analysis:
    - File: `/code/oauth/views.py`
    - Function: `RequireEmailView.form_valid(self, form)`
    ```python
    def form_valid(self, form):
        email = form.cleaned_data['email']
        oauthid = form.cleaned_data['oauthid']
        oauthuser = get_object_or_404(OAuthUser, pk=oauthid)
        oauthuser.email = email # Vulnerable line: Directly assigns the provided email
        oauthuser.save()
        sign = get_sha256(settings.SECRET_KEY +
                          str(oauthuser.id) + settings.SECRET_KEY)
        site = get_current_site().domain
        if settings.DEBUG:
            site = '127.0.0.1:8000'
        path = reverse('oauth:email_confirm', kwargs={
            'id': oauthid,
            'sign': sign
        })
        url = "http://{site}{path}".format(site=site, path=path)

        content = _("""
               <p>Please click the link below to bind your email</p>

                 <a href="%(url)s" rel="bookmark">%(url)s</a>

                 Thank you again!
                 <br />
                 If the link above cannot be opened, please copy this link to your browser.
                  <br />
                 %(url)s
                """) % {'url': url}
        send_email(emailto=[email, ], title=_('Bind your email'), content=content) # Sends confirmation email, but after email is already assigned
        url = reverse('oauth:bindsuccess', kwargs={
            'oauthid': oauthid
        })
        url = url + '?type=email'
        return HttpResponseRedirect(url)
    ```
    - In the `form_valid` function of `RequireEmailView`, the email address provided by the attacker via the `RequireEmailForm` is directly assigned to the `oauthuser.email` field without checking if this email is already associated with another user.
    - The subsequent `send_email` function dispatches a signal to send a confirmation email to the provided address, but this is only for email verification *after* the email has been assigned. There is no check to prevent assigning an email already in use by another account before sending the confirmation email.
    - The `emailconfirm` view then proceeds to link the OAuth user to a `BlogUser` with the provided email, creating a new user if one doesn't exist or linking to an existing one if it does, effectively taking over the account associated with that email if it already exists.

- Security test case:
    1. Create two user accounts on the DjangoBlog platform:
        - User A: `usera@example.com` (via standard registration or any OAuth method).
        - User B: `userb@example.com` (via standard registration or any OAuth method).
    2. As attacker, initiate an OAuth login using an OAuth provider that triggers the email requirement step (e.g., GitHub if email privacy settings prevent email disclosure).
    3. When prompted for an email address, enter the email address of User A: `usera@example.com`.
    4. Complete the OAuth email binding process.
    5. Log out of any existing DjangoBlog sessions.
    6. Log in to DjangoBlog using the OAuth account created in step 2.
    7. Observe that you are now logged in as User A, and can access and control User A's account.
    8. Repeat steps 2-7, but this time enter the email address of User B: `userb@example.com`.
    9. Observe that you are now logged in as User B, and can access and control User B's account.

This test case demonstrates that an attacker can take over any existing account by simply providing the target user's email address during the OAuth email binding process.