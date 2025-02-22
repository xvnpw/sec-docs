## Combined Vulnerability List for django-guardian

This document consolidates vulnerabilities identified in django-guardian, aiming to provide a comprehensive view for developers and security auditors. Each vulnerability is described in detail, including steps to trigger it, potential impact, and recommended mitigations.

### Insecure Direct Object Reference in Permission Checks

**Vulnerability Name:** Insecure Direct Object Reference in Permission Checks

**Description:**
If `django-guardian` is used in a way that relies on direct object IDs from URL parameters or request data to perform permission checks without proper validation of object ownership or access rights beyond the ID itself, an external attacker could potentially manipulate these object IDs to attempt to access or modify objects they are not authorized to interact with.

For example, consider an application using URLs like `/objects/<object_id>/edit/` and `django-guardian` checking permissions based on this `object_id`. If the permission check only verifies that the user has *some* permission on *an* object of that type, and not specifically on the object identified by `<object_id>`, an attacker could try to increment or decrement `<object_id>` to guess IDs of other objects and potentially gain unauthorized access to them.

**Step-by-step trigger:**
1. An attacker identifies a URL in the application that uses an object ID to access a resource protected by `django-guardian`, for example: `/documents/123/view/`.
2. The attacker understands that `django-guardian` is likely used to control access to these documents.
3. The attacker might have legitimate access to view document `123`.
4. The attacker then attempts to access other documents by modifying the `object_id` in the URL, for example, changing `123` to `124`, `125`, etc., or trying sequential IDs.
5. If `django-guardian` permission checks are not properly validating if the user is authorized to access the *specific* object ID requested (e.g., document `124`), but only checking if the user has *any* 'view_document' permission, the attacker might successfully bypass the intended access control and view document `124` even if they should not have permission for it.

**Impact:**
Unauthorized access to sensitive objects. This can lead to:
- **Data leakage:** Attackers can view confidential information they are not supposed to see.
- **Data modification:** In more severe cases, if the vulnerability exists in endpoints allowing modifications (e.g., `/objects/<object_id>/edit/`), attackers could modify or delete data they are not authorized to manage.
- **Integrity compromise:** Unauthorized modifications can compromise the integrity and reliability of the application's data.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- None identified in `django-guardian` core related to preventing insecure direct object reference in application usage. `django-guardian` provides tools for permission checking, but the responsibility of correctly implementing secure object-level checks falls on the application developer.

**Missing Mitigations:**
- **Guidance and best practices in documentation:** `django-guardian` documentation should strongly emphasize the importance of implementing robust object-level permission checks that go beyond just checking for the existence of *a* permission and explicitly validate access to the *specific* object being accessed.
- **Example code snippets and patterns:** Provide examples of how to correctly use `django-guardian` to prevent insecure direct object references, showcasing how to validate object ownership or specific access rights within permission checks.

**Preconditions:**
- Application uses `django-guardian` for permission management.
- Application URLs or request data rely on direct object IDs to access resources.
- `django-guardian` permission checks in the application are not implemented to specifically validate access to the requested object ID, but instead rely on broader permission checks that might be bypassed by manipulating object IDs.

**Source Code Analysis:**
`django-guardian` itself does not inherently cause this vulnerability. The vulnerability arises from how developers *use* `django-guardian` in their applications.

Let's illustrate a vulnerable code pattern (example in Django view):

```python
# Vulnerable View Example (Conceptual - Not from django-guardian core)
from django.shortcuts import get_object_or_404
from django.http import HttpResponseForbidden
from guardian.decorators import permission_required

def document_view(request, document_id):
    document = get_object_or_404(Document, pk=document_id) # Get document by ID
    if not request.user.has_perm('view_document', document): # Check general 'view_document' permission
        return HttpResponseForbidden("You do not have permission to view this document.")
    return render(request, 'document_view.html', {'document': document})
```

**Explanation of Vulnerability in Example:**
1. The view retrieves a `Document` object based on `document_id` from the URL.
2. It then uses `request.user.has_perm('view_document', document)`.  While `has_perm` uses `django-guardian` to check permissions, if the `view_document` permission is granted too broadly (e.g., to all authenticated users or based on group membership without object-level context), it becomes vulnerable.
3. The issue is that `has_perm('view_document', document)` might only check if the user has *any* 'view_document' permission related to *documents* in general, but not specifically for *this* `document` object.
4. An attacker who has 'view_document' permission (perhaps for a different document) could potentially access *any* document by simply changing the `document_id` in the URL, as the permission check does not ensure they are authorized for *that specific document*.

**Corrected Code Pattern (Example):**

```python
# Mitigated View Example (Conceptual)
from django.shortcuts import get_object_or_404
from django.http import HttpResponseForbidden
from guardian.decorators import permission_required

def document_view(request, document_id):
    document = get_object_or_404(Document, pk=document_id)
    if not request.user.has_perm('view_document', document): # Still using has_perm
        return HttpResponseForbidden("You do not have permission to view this document.")
    # ADDITIONALLY, perform object-level check if needed, depending on application logic
    # For example, check if document belongs to user's organization, etc.
    if not document.organization in request.user.organizations.all(): # Example object-level check
        return HttpResponseForbidden("You do not have permission to view documents from this organization.")
    return render(request, 'document_view.html', {'document': document})
```

**Explanation of Mitigation:**
- The corrected example *adds* an explicit object-level check after the `django-guardian` permission check.
- `document.organization in request.user.organizations.all()` is a placeholder for a more specific application-dependent check.  This check ensures that even if the user has a general 'view_document' permission, they are still only allowed to view documents belonging to their organization.
- The specific object-level check will vary based on the application's access control requirements.  It might involve checking object ownership, group membership related to the object, or other relevant criteria.

**Security Test Case:**
1. **Setup:** Create two users, User A and User B. Create two Document objects, Document 1 (ID: 1) and Document 2 (ID: 2). Configure permissions such that User A should only have 'view_document' permission for Document 1, and User B should not have 'view_document' permission for either document (or has 'view_document' for a different document, ID: 3, for example, to simulate a user with some legitimate permission).
2. **Login as User A.**
3. **Access Document 1:** Navigate to `/documents/1/view/`. Verify that User A can successfully view Document 1.
4. **Attempt to access Document 2:** Navigate to `/documents/2/view/`.
5. **Expected Result:** User A should *not* be able to view Document 2. The application should either return a 403 Forbidden error or redirect to a permission denied page. If User A *can* view Document 2, it indicates an Insecure Direct Object Reference vulnerability.
6. **Login as User B.**
7. **Attempt to access Document 1 and Document 2:** Navigate to `/documents/1/view/` and `/documents/2/view/`.
8. **Expected Result:** User B should *not* be able to view either Document 1 or Document 2.  If User B *can* view either document, it further confirms the Insecure Direct Object Reference vulnerability and highlights a broader permission bypass.


### Insecure Default Configuration in Example Project Settings (DEBUG True & Weak SECRET_KEY)

**Vulnerability Name:** Insecure Default Configuration in Example Project Settings (DEBUG True & Weak SECRET_KEY)

**Description:**
The example project’s settings file defines dangerous defaults that could easily be left unmodified when deploying to production. In particular:
- `DEBUG` is set to `True`, which causes full stack traces and sensitive configuration details to be exposed when errors occur.
- `SECRET_KEY` is hard-coded to a weak placeholder value (for example, `'CHANGE_THIS_TO_SOMETHING_UNIQUE_AND_SECURE'`) that is predictable.
An external attacker can deliberately trigger errors (or otherwise exploit debugging output) to extract sensitive internal details and may compromise session integrity because all signing is done using this insecure key.

**Step-by-step trigger:**
1. Deploy the project “as is” without modifying the `DEBUG` and `SECRET_KEY` settings.
2. An attacker navigates to a URL known to trigger an exception or internal error within the application. Alternatively, they may observe debugging output from other application behaviors.

**Impact:**
- Disclosure of sensitive application and configuration details via debug error pages.
- Increased risk of session hijacking, cryptographic attacks, and unauthorized access due to the use of a predictable secret key.

**Vulnerability Rank:** Critical

**Currently Implemented Mitigations:**
- Inline comments and documentation in the settings file advise developers to change the default secret key.
- The insecure defaults are intended solely as a starting point for development, not for a production environment.

**Missing Mitigations:**
- No runtime enforcement (for example, through environment‑based configuration or production startup checks) that prevents running with `DEBUG=True` or with the weak default secret key.
- No fallback mechanism to automatically load a secure, random key from environment variables when deployed in production.

**Preconditions:**
- The application is deployed in a production or publicly accessible environment without overriding the default insecure configuration values.

**Source Code Analysis:**
- In the example project’s settings file (e.g. `/code/example_project/settings.py`), you will see the following:
  ```python
  DEBUG = True
  SECRET_KEY = 'CHANGE_THIS_TO_SOMETHING_UNIQUE_AND_SECURE'
  ```
- No runtime or startup-time checks ensure that these values have been overridden before deployment.

**Security Test Case:**
1. Deploy the project “as is” without modifying the `DEBUG` and `SECRET_KEY` settings.
2. Navigate to a URL known to trigger an exception or internal error.
3. Confirm that the error page displays a full stack trace along with internal configuration details.
4. Inspect session cookies and any signed tokens to verify that they are signed using the known default (and insecure) secret key.
5. A positive result confirms that an attacker could exploit these defaults to gather sensitive information or compromise session integrity.


### Orphaned Object Permissions Leading to Privilege Escalation

**Vulnerability Name:** Orphaned Object Permissions Leading to Privilege Escalation

**Description:**
The object‑level permission system is implemented using generic associations—permission records are stored with fields such as `object_pk` and are not tightly bound via enforced foreign key constraints to the target objects. This design means that when a target object or user/group is deleted, its corresponding permission records are not automatically removed. If a new object (or user/group) is later created and receives an identifier that collides with a deleted one, the orphaned permission records may inadvertently grant access to this new entity.

**Step-by-step trigger:**
1. An object (e.g., a Post) is created and assigned a unique primary key (e.g., pk=1).
2. Object-level permissions are granted to users or groups for this object (e.g., user 'testuser' is granted 'view_post' permission on Post with pk=1). These permissions are stored in `UserObjectPermission` or `GroupObjectPermission` tables, referencing the object using generic foreign keys (`content_type`, `object_pk`).
3. The original object (Post with pk=1) is deleted.
4. The associated object permissions in `UserObjectPermission` and `GroupObjectPermission` tables are **not automatically deleted**. These permissions become "orphaned" as they point to a non-existent object.
5. Subsequently, a new object of the same type (another Post) is created. Depending on database behavior and primary key generation, this new object might be assigned the **same primary key (pk=1)** as the previously deleted object.
6. Due to the orphaned permissions, users or groups who were granted permissions on the *old*, deleted object now **inadvertently gain the same permissions on the *new* object** with the same primary key. This occurs because the object permission records still exist and match the `content_type` and `object_pk` of the newly created object.

**Impact:**
Unauthorized access to objects. Users may gain permissions to view, change, or delete objects they should not have access to, leading to data leakage or data manipulation. In scenarios with sensitive data or critical operations, this can have significant security consequences.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The documentation alerts developers to the risk and recommends manually connecting Django signals or invoking manual cleanup routines.
- A management command (`clean_orphan_obj_perms`) is provided to allow system administrators to remove orphaned permission entries.
- The project provides a utility function `clean_orphan_obj_perms` (documented in `docs/userguide/caveats.md` and implemented in `guardian/utils.py`) to manually remove orphaned object permissions.
- Documentation in `docs/userguide/caveats.md` advises developers to explicitly remove object permissions when objects are deleted and provides an example using Django signals (`pre_delete`).

**Missing Mitigations:**
- There is no built‑in automatic cascading or background cleanup process that prevents orphaned permission records from persisting.
- No runtime signals or scheduled tasks are installed by default to enforce the removal of orphaned permission entries.
- **Automatic deletion of object permissions:** The project lacks built-in automatic mechanisms to remove associated object permissions when a Django model instance is deleted. This could be implemented using Django signals (e.g., `pre_delete` or `post_delete` signals on models for which object permissions are managed).
- **Enforced explicit permission cleanup:**  There is no enforced mechanism to ensure developers implement explicit permission cleanup in their applications. Reliance on manual cleanup or optional utilities increases the risk of vulnerabilities.

**Preconditions:**
- An object (or user/group) that has object‑level permissions is deleted without its associated permission records being removed.
- Subsequently, a new object (or user/group) is created that reuses the same primary key or identifier used before, leading to an unintended permission grant.
- The application uses generic foreign keys for object permissions (which is the default in django-guardian). This vulnerability is noted as not applicable when using direct foreign keys as described in `docs/userguide/performance.md#direct-foreign-keys`.
- Objects for which object permissions are defined are deleted without explicitly removing the associated object permissions using `guardian.shortcuts.remove_perm` or a similar cleanup mechanism.
- The database primary key mechanism allows for reuse of primary keys after object deletion (this is database-dependent but common behavior, especially with auto-incrementing integer primary keys).

**Source Code Analysis:**
- In the guardian code (see `/code/guardian/utils.py`), the function `clean_orphan_obj_perms()` iterates over permission records:
  ```python
  for perm in chain(UserObjectPermission.objects.all().iterator(),
                    GroupObjectPermission.objects.all().iterator()):
      if perm.content_object is None:
          logger.debug("Removing %s (pk=%d)" % (perm, perm.pk))
          perm.delete()
  ```
- Because the deletion of the target object does not automatically cascade to delete the associated generic permission record, these “orphaned” entries continue to exist until manually cleaned.
- **`guardian/utils.clean_orphan_obj_perms`**: This utility function is designed to *mitigate* the issue *after* it has occurred. It works by:
    * Querying `UserObjectPermission` and `GroupObjectPermission` models.
    * For each permission record, attempting to fetch the `content_object` using the generic foreign key (`content_type`, `object_pk`).
    * If the `content_object` does not exist (returns `None`), the permission record is considered orphaned and is deleted.
- **Missing Automatic Cleanup**: The core django-guardian code does not include any automatic cleanup of object permissions upon object deletion. The responsibility for preventing orphaned permissions is placed on the application developer.
- **Documentation Caveat**: The `docs/userguide/caveats.md` file explicitly warns about orphaned object permissions and states: "It is **extremely** important to remove `UserObjectPermission` and `GroupObjectPermission` as we delete objects for which permissions are defined." The documentation provides an example of using a `pre_delete` signal to remove permissions when a `User` object is deleted.
- **Test Case (`/code/guardian/testapp/tests/test_orphans.py`)**: The project includes a test suite, and the file `/code/guardian/testapp/tests/test_orphans.py` specifically tests the `clean_orphan_obj_perms` utility function. This test implicitly acknowledges and validates the existence of orphaned object permissions as a potential issue if not handled properly. The test checks if `clean_orphan_obj_perms` correctly removes orphaned permissions after target objects are deleted, further highlighting the vulnerability when objects are deleted without explicit permission cleanup.

**Security Test Case:**
1. In a controlled test environment, create an object (or user/group) and assign it an object‑level permission.
2. Delete that object (or user/group) using Django’s ORM so that the permission record remains.
3. Manually create (or force the creation of) a new object (or user/group) with the same identifier as the deleted one.
4. Log in using the credentials that originally held the permission and attempt to access or operate on the new object.
5. If the permission check erroneously grants access, the vulnerability has been successfully reproduced.
- **Setup:**
    * In the example project (or a test environment using django-guardian), create a `Post` model instance named 'test_post' with `slug='test-post'`.
    * Create a regular user 'testuser'.
    * Assign the 'view_post' permission to 'testuser' for 'test_post' using `assign_perm('posts.view_post', testuser, test_post)`.
    * Verify that 'testuser' has the 'view_post' permission for 'test_post' (e.g., using `testuser.has_perm('posts.view_post', test_post)`).
- **Exploit:**
    * Delete the 'test_post' object using `test_post.delete()`. **Crucially, do not explicitly remove object permissions before deletion.**
    * Create a *new* `Post` model instance, also named 'new_post', with `slug='new-post'`. Check (and if necessary, manipulate database sequence/IDs) to ensure this new 'new_post' object gets assigned the **same primary key** as the deleted 'test_post' object.  You might need to inspect the database or use database-specific commands to influence primary key assignment for testing purposes.
- **Verification:**
    * Check if 'testuser' now *inadvertently* has the 'view_post' permission for the *new* 'new_post' object using `testuser.has_perm('posts.view_post', new_post)`.
    * **If `testuser.has_perm('posts.view_post', new_post)` returns `True`, the vulnerability is confirmed.** This indicates that the orphaned permission from the deleted 'test_post' is now incorrectly granting access to the 'new_post' object due to primary key reuse.
- **Existing Test Confirmation**: The presence of the test suite and specifically the tests in `/code/guardian/testapp/tests/test_orphans.py` can be seen as an existing, albeit implicit, confirmation of this security test case. These tests demonstrate the mechanism of orphaned permissions and the need for cleanup, aligning with the described vulnerability scenario.


### Unverified Monkey Patching of User and Group Models

**Vulnerability Name:** Unverified Monkey Patching of User and Group Models

**Description:**
To support object‑level permissions easily, the library performs monkey patching on Django’s User and Group models at runtime. This is done by directly assigning convenience methods (e.g. `get_anonymous`, `add_obj_perm`, `del_obj_perm`) to the model classes without performing any subsequent integrity or authenticity verifications. If an attacker (or an insider with write access to the deployment) manages to influence the module load order or modify the patched methods on disk, they could replace or alter the permission-checking functionality.

**Step-by-step trigger:**
1. An attacker gains write access to the deployment environment, or is able to influence the module load order (e.g., through a compromised dependency).
2. The attacker modifies the patched methods of the User or Group models on disk, replacing them with malicious implementations.
3. The application, upon startup or during runtime if modules are reloaded, will use these compromised methods for permission checks.

**Impact:**
- An attacker could override these critical methods to assign or revoke permissions without proper verification, thereby bypassing authorization checks.
- Such an exploit could lead to privilege escalation and unauthorized access across the application.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
- The patching behavior is controlled by configuration settings (e.g. `GUARDIAN_MONKEY_PATCH_USER` and `GUARDIAN_MONKEY_PATCH_GROUP`), which allow administrators to disable monkey patching.
- The patching is executed only once during application startup.

**Missing Mitigations:**
- There is no runtime integrity verification of the patched methods after they are applied.
- No built‑in safeguards (for example, cryptographic signing or rigorous hash checking) exist to detect if the patched functions have been altered during runtime.
- The system relies solely on external filesystem and deployment security, with no internal defense against patch manipulation.

**Preconditions:**
- The application is deployed with monkey patching enabled (the default is typically enabled when not explicitly disabled).
- An attacker is able to influence module load order or modify files on disk (via a compromised dependency or misconfigured file permissions) such that the patched methods can be replaced or altered.

**Source Code Analysis:**
- In the library’s initialization code (for example, in files such as `guardian/__init__.py` and `guardian/apps.py`), the patching is implemented as follows:
  ```python
  setattr(User, 'get_anonymous', staticmethod(lambda: get_anonymous_user()))
  setattr(User, 'add_obj_perm', lambda self, perm, obj: UserObjectPermission.objects.assign_perm(perm, self, obj))
  setattr(User, 'del_obj_perm', lambda self, perm, obj: UserObjectPermission.objects.remove_perm(perm, self, obj))
  ```
- No later verification or integrity check is performed, meaning that if these attributes are altered after startup, the system will use the modified (and possibly insecure) implementations.

**Security Test Case:**
1. Deploy the application in a controlled environment with monkey patching enabled.
2. Verify that the User model contains the expected methods by calling, for example, `user.add_obj_perm` and confirming the normal behavior.
3. Manually (or via a simulated attack) reassign one of the patched methods—for instance, override `User.add_obj_perm` with a function that always returns success without performing any permission checks.
4. Attempt to use this altered method to assign a permission to a sensitive object.
5. If the permission check is bypassed, this confirms that the lack of runtime integrity verification in the monkey patching mechanism exposes a critical vulnerability.