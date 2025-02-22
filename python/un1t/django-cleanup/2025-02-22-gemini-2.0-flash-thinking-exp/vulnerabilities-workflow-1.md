## Vulnerability List

The following vulnerability has been identified in the project. It allows for path traversal during file deletion, potentially leading to the deletion of arbitrary files outside the intended media directory.

### Vulnerability Name: Path Traversal in File Deletion Mechanism

### Description:
The django‐cleanup package automatically deletes old files for FileField (and subclasses) when a record is updated or deleted. In the deletion process (in the function `delete_file` in *handlers.py*), the file’s name is taken directly from the field object (via `file_.name`) and is passed to the storage backend’s delete method without additional sanitization. An external attacker that is able to update a model instance’s file field value (for example, via an exposed or mis‐configured update endpoint) can supply a path traversal payload (e.g. a value such as `"../../sensitive_file"`). When the cleanup logic compares the new file value with the cached “old” file and then calls `file_.delete(save=False)` inside an on_commit callback, the backend storage (commonly using Django’s FileSystemStorage) may resolve the malicious path and end up deleting an unintended file outside the designated media directory.

*Step‑by‑Step Trigger:*
1. An attacker identifies a publicly accessible endpoint (or misconfigured API) that allows updates to a model instance’s FileField.
2. The attacker submits an update request with a malicious file field value (for example, `"../../etc/passwd"` or any path traversal string) while an existing valid file (e.g. `"uploads/legit.jpg"`) is cached.
3. On saving the updated model instance, the post_save signal is triggered, and the function `delete_old_post_save` compares the old file (stored in the cache) with the new file value.
4. When the old file does not match the new (malicious) file value, the cleanup logic calls `delete_file` which, after minimal checks (only that the file name is nonempty and not equal to a default), proceeds to call the deletion routine.
5. The storage backend’s delete method is invoked using the supplied file name, and if the storage backend does not enforce a strict safe-joining of paths, the malicious traversal payload causes an arbitrary file outside the expected directory to be deleted.

### Impact:
If exploited, an attacker could delete critical files from the system (for example, files outside the intended media folder), leading to data loss and system integrity compromise. In a worst-case scenario—if the application user running the server has high privileges—this could even lead to a full compromise or instability of the service.

### Vulnerability Rank: Critical

### Currently Implemented Mitigations:
- The deletion process is indirectly “protected” by relying on Django’s FileField and its storage backend. In many setups the default storage may perform some form of normalization on file paths.
- The logic does compare file names with a default value to avoid deleting files that have not really changed.

### Missing Mitigations:
- No explicit sanitization or validation of the file name (i.e. checking for directory traversal sequences such as "../") is performed before deletion.
- There is no verification ensuring that the file to be deleted resides within the designated media directory.
- Additional authorization or input validation for updates that trigger cleanup is not enforced at the cleanup layer (it is assumed to be handled at the application level, but its absence in the cleanup logic introduces risk when misconfigured).

### Preconditions:
- The application using django-cleanup is publicly accessible and permits updates on model instances that include FileField values without robust authorization or input validation.
- The storage backend (e.g. a FileSystemStorage instance) does not enforce strict safeguards against path traversal or unsafe file delete paths.
- An attacker must have a way (directly or indirectly) to submit a file field update with a crafted (malicious) file name.

### Source Code Analysis:
- In `handlers.delete_file` (lines around the on_commit callback), the code first checks:
    - If `file_.name` is empty, it returns immediately.
    - It sets `file_.instance` to a `FakeInstance` and ensures that both `file_.field` and `file_.storage` are correctly set (restoring these values from cached dotted paths via `cache.get_field` and `cache.get_field_storage`).
    - It then computes a “default” value (using `file_.field.default` or its callable form) and, if the old file name equals this default, it skips deletion.
    - Otherwise, without any sanitization of the contents of `file_.name`, it calls `file_.delete(save=False)` within an `on_commit` callback.
- Since `file_.name` is used directly, if an attacker can cause the new file value to be something like `"../../<malicious_path>"`, and if the underlying storage backend does not perform safe path joining, the deletion may target an unintended file location.

### Security Test Case:
1. Deploy the application with django-cleanup enabled and configure it to use a FileSystemStorage backend without additional filename sanitization.
2. Create a model instance via a public interface with a valid file upload (e.g. with a file name `"uploads/legit.jpg"`) so that the cleanup cache is properly populated with the existing file name.
3. From an attacker’s perspective, send an update request to the same endpoint, supplying a value in the file field that includes a directory traversal payload (for example: `"../../sensitive_file"`).
4. Commit the change (or trigger a save) so that the post_save signal fires and `delete_old_post_save` is executed.
5. Monitor the filesystem to check whether the file deletion routine attempts to remove a file outside the intended directory (for example, verifying that `/etc/sensitive_file` or another out-of-bound path is targeted).
6. Verify via logs that the deletion operation was attempted (or succeeded) using the malicious path.

*Note:* Although django-cleanup is designed as a utility to help manage file deletion on model changes, its design assumes that the application using it has proper authorization and input validation controls in place. If those controls are lacking or misconfigured, the cleanup logic’s lack of filename sanitization can be exploited by an external attacker.