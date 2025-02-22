### Vulnerability List

* Vulnerability Name: Orphaned Object Permissions leading to Privilege Escalation

* Description:
    1. An object (e.g., a Post) is created and assigned a unique primary key (e.g., pk=1).
    2. Object-level permissions are granted to users or groups for this object (e.g., user 'testuser' is granted 'view_post' permission on Post with pk=1). These permissions are stored in `UserObjectPermission` or `GroupObjectPermission` tables, referencing the object using generic foreign keys (`content_type`, `object_pk`).
    3. The original object (Post with pk=1) is deleted.
    4. **Vulnerability:** The associated object permissions in `UserObjectPermission` and `GroupObjectPermission` tables are **not automatically deleted**. These permissions become "orphaned" as they point to a non-existent object.
    5. Subsequently, a new object of the same type (another Post) is created. Depending on database behavior and primary key generation, this new object might be assigned the **same primary key (pk=1)** as the previously deleted object.
    6. **Privilege Escalation:** Due to the orphaned permissions, users or groups who were granted permissions on the *old*, deleted object now **inadvertently gain the same permissions on the *new* object** with the same primary key. This occurs because the object permission records still exist and match the `content_type` and `object_pk` of the newly created object.

* Impact:
    Unauthorized access to objects. Users may gain permissions to view, change, or delete objects they should not have access to, leading to data leakage or data manipulation. In scenarios with sensitive data or critical operations, this can have significant security consequences.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
    * The project provides a utility function `clean_orphan_obj_perms` (documented in `docs/userguide/caveats.md` and implemented in `guardian/utils.py`) to manually remove orphaned object permissions.
    * Documentation in `docs/userguide/caveats.md` advises developers to explicitly remove object permissions when objects are deleted and provides an example using Django signals (`pre_delete`).

* Missing Mitigations:
    * **Automatic deletion of object permissions:** The project lacks built-in automatic mechanisms to remove associated object permissions when a Django model instance is deleted. This could be implemented using Django signals (e.g., `pre_delete` or `post_delete` signals on models for which object permissions are managed).
    * **Enforced explicit permission cleanup:**  There is no enforced mechanism to ensure developers implement explicit permission cleanup in their applications. Reliance on manual cleanup or optional utilities increases the risk of vulnerabilities.

* Preconditions:
    * The application uses generic foreign keys for object permissions (which is the default in django-guardian). This vulnerability is noted as not applicable when using direct foreign keys as described in `docs/userguide/performance.md#direct-foreign-keys`.
    * Objects for which object permissions are defined are deleted without explicitly removing the associated object permissions using `guardian.shortcuts.remove_perm` or a similar cleanup mechanism.
    * The database primary key mechanism allows for reuse of primary keys after object deletion (this is database-dependent but common behavior, especially with auto-incrementing integer primary keys).

* Source Code Analysis:
    1. **`guardian/utils.clean_orphan_obj_perms`**: This utility function is designed to *mitigate* the issue *after* it has occurred. It works by:
        * Querying `UserObjectPermission` and `GroupObjectPermission` models.
        * For each permission record, attempting to fetch the `content_object` using the generic foreign key (`content_type`, `object_pk`).
        * If the `content_object` does not exist (returns `None`), the permission record is considered orphaned and is deleted.
    2. **Missing Automatic Cleanup**: The core django-guardian code does not include any automatic cleanup of object permissions upon object deletion. The responsibility for preventing orphaned permissions is placed on the application developer.
    3. **Documentation Caveat**: The `docs/userguide/caveats.md` file explicitly warns about orphaned object permissions and states: "It is **extremely** important to remove `UserObjectPermission` and `GroupObjectPermission` as we delete objects for which permissions are defined." The documentation provides an example of using a `pre_delete` signal to remove permissions when a `User` object is deleted.
    4. **Test Case (`/code/guardian/testapp/tests/test_orphans.py`)**: The project includes a test suite, and the file `/code/guardian/testapp/tests/test_orphans.py` specifically tests the `clean_orphan_obj_perms` utility function. This test implicitly acknowledges and validates the existence of orphaned object permissions as a potential issue if not handled properly. The test checks if `clean_orphan_obj_perms` correctly removes orphaned permissions after target objects are deleted, further highlighting the vulnerability when objects are deleted without explicit permission cleanup.

* Security Test Case:
    1. **Setup:**
        * In the example project (or a test environment using django-guardian), create a `Post` model instance named 'test_post' with `slug='test-post'`.
        * Create a regular user 'testuser'.
        * Assign the 'view_post' permission to 'testuser' for 'test_post' using `assign_perm('posts.view_post', testuser, test_post)`.
        * Verify that 'testuser' has the 'view_post' permission for 'test_post' (e.g., using `testuser.has_perm('posts.view_post', test_post)`).
    2. **Exploit:**
        * Delete the 'test_post' object using `test_post.delete()`. **Crucially, do not explicitly remove object permissions before deletion.**
        * Create a *new* `Post` model instance, also named 'new_post', with `slug='new-post'`. Check (and if necessary, manipulate database sequence/IDs) to ensure this new 'new_post' object gets assigned the **same primary key** as the deleted 'test_post' object.  You might need to inspect the database or use database-specific commands to influence primary key assignment for testing purposes.
    3. **Verification:**
        * Check if 'testuser' now *inadvertently* has the 'view_post' permission for the *new* 'new_post' object using `testuser.has_perm('posts.view_post', new_post)`.
        * **If `testuser.has_perm('posts.view_post', new_post)` returns `True`, the vulnerability is confirmed.** This indicates that the orphaned permission from the deleted 'test_post' is now incorrectly granting access to the 'new_post' object due to primary key reuse.
    4. **Existing Test Confirmation**: The presence of the test suite and specifically the tests in `/code/guardian/testapp/tests/test_orphans.py` can be seen as an existing, albeit implicit, confirmation of this security test case. These tests demonstrate the mechanism of orphaned permissions and the need for cleanup, aligning with the described vulnerability scenario.