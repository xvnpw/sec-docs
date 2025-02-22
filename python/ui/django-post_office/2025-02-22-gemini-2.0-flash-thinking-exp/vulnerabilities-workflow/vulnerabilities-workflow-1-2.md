- **Vulnerability Name:** Arbitrary File Read via Attachment Parameter
  - **Description:**
    When an email is “sent” by the library, the developer may pass an `attachments` parameter to the `mail.send()` function. In the helper function `create_attachments()` (located in `post_office/utils.py`), any attachment value that is of type string is assumed to be a file name or file path and is immediately used to open a file (using Python’s built‑in `open()` call) without any sanitization or validation. This means that if an attacker can control the value passed as an attachment (or if a public endpoint later exposes this functionality), they can supply an arbitrary absolute or relative file path (for example, `/etc/passwd` on Unix systems). When the file is opened and read, its contents become attached to the outgoing email. If the attacker can also control the recipient address (or if a misconfiguration overrides recipients), they can cause the sensitive file’s content to be delivered to an attacker‑controlled mailbox.

    **Step‑by-step trigger process:**
    1. An external attacker sends a crafted request to a publicly exposed endpoint that (directly or indirectly) calls `mail.send()`.
    2. In the request, the attacker supplies—for example—in the JSON body or form parameter an `attachments` dictionary where one key is a filename (say `"sensitive.txt"`) and its value is a string containing an arbitrary file path (e.g. `/etc/passwd`).
    3. Inside the `create_attachments()` function, the code detects that the attachment value is a `str` and calls `open(content, 'rb')` on it.
    4. The file is read and attached (via Django’s File API) for inclusion in the email message.
    5. The email is dispatched (either immediately or through the queued process) and delivered to the attacker‑controlled recipient.

  - **Impact:**
    An attacker may read any local file that the application process has permission to read. This could result in:
    - Disclosure of sensitive operating system files (e.g. `/etc/passwd` or configuration files containing secrets).
    - Exposure of internal credentials or private data stored on the disk.
    - Full compromise of sensitive system information leading to further attacks.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - The code expects attachments to normally be passed as file‑like objects (or in other well‑structured formats) and does not perform explicit checks when a string is provided.
    - There is no built‑in sanitization or restriction on file paths.

  - **Missing Mitigations:**
    - Validate and sanitize any file input provided as a string.
    - Enforce a whitelist or restrict file paths to a safe directory so that arbitrary files on the system cannot be read.
    - Require that attachments be passed as already‑opened file‑like objects (or wrap file input in an abstraction that validates its source) rather than allowing raw file paths.

  - **Preconditions:**
    - The application exposes an endpoint or mechanism that passes external (potentially untrusted) input to `mail.send()` without additional sanitization.
    - The attacker can control both the `attachments` parameter (to insert a file path) and the recipient address (so that the email is delivered to them).
    - The server process has read access to sensitive files (for example, system files such as `/etc/passwd`).

  - **Source Code Analysis:**
    In the file **post_office/utils.py**, observe the following excerpt in the `create_attachments()` function:
    ```python
      def create_attachments(attachment_files):
          attachments = []
          for filename, filedata in attachment_files.items():
              # If the value is a dict, extract file-like object and mimetype.
              # Otherwise, assume that filedata is either already a file-like object or a filename.
              if isinstance(filedata, dict):
                  content = filedata.get('file', None)
                  mimetype = filedata.get('mimetype', None)
                  headers = filedata.get('headers', None)
              else:
                  content = filedata
                  mimetype = None
                  headers = None

              opened_file = None

              if isinstance(content, str):
                  # `content` is a filename - try to open the file
                  opened_file = open(content, 'rb')
                  content = File(opened_file)
              ...
              attachment.file.save(filename, content=content, save=True)
              attachments.append(attachment)
              if opened_file is not None:
                  opened_file.close()
          return attachments
    ```
    Notice that if a string is provided (i.e. if `isinstance(content, str)` is true), the code immediately uses `open(content, 'rb')` without any check to ensure that the path is safe or part of an allowed directory. This unsanitized use of file paths leads directly to the described arbitrary file read.

  - **Security Test Case:**
    1. **Setup:** Deploy a test instance of the application with an endpoint that ultimately calls `mail.send()` (or `send_many()`) without further sanitization. Ensure that the system has a file (e.g., `/etc/passwd` on a Unix system) that the process can read.
    2. **Request Crafting:**
       - Prepare an HTTP request (for example, a POST request) that supplies the following JSON or form parameters:
         - `"recipients": ["attacker@example.com"]` (or any attacker‑controlled email address)
         - `"sender": "any@example.com"`
         - Other required parameters such as `"subject": "Test"`
         - `"attachments": { "sensitive.txt": "/etc/passwd" }`
    3. **Execution:** Send the request to the application’s endpoint.
    4. **Observation:**
       - Monitor the outgoing email (using a test mailbox or intercepting SMTP traffic) delivered to the attacker's email address.
       - Verify that an attachment named “sensitive.txt” is included and that its content matches that of the system file (e.g., `/etc/passwd`).
    5. **Expected Result:** The attached file in the delivered email contains the contents from `/etc/passwd`, confirming that arbitrary file read is possible.
    6. **Cleanup:** Ensure that such testing is performed in an isolated environment only.