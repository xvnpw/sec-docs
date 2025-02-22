- **Vulnerability Name:** Insecure Deserialization via Pickle in Task Payloads
  **Description:**
  An attacker who can inject or tamper with queued task messages may craft a malicious payload that, when deserialized via Python’s unsafe `pickle.loads`, causes arbitrary code execution. In this project the task payloads are wrapped inside a signing mechanism (using the project’s SECRET_KEY and prefix) and then unserialized by a custom serializer. However, because the underlying deserialization uses the unsafe `pickle` module without any restrictions or type‐whitelisting, an attacker who either can compromise the broker (for example, via a misconfigured or exposed Redis, Disque, or Mongo instance) or knows/forges the signature (if the SECRET_KEY is weak or exposed) may successfully inject a malicious payload.
  **Impact:**
  Exploitation of this vulnerability can lead to remote code execution (RCE) on the host running worker processes. An attacker may execute arbitrary system commands with the same privileges as the process, compromising confidentiality, integrity, and availability of the system.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - Task payloads are signed (using Django’s signing methods in the project’s `SignedPackage` and related serializer classes) so that any alteration of the payload should, in theory, invalidate the signature.
  - Deserialization is performed only after a successful signature check.
  **Missing Mitigations:**
  - The project still relies entirely on Python’s built‑in `pickle` module for (de)serialization without additional runtime restrictions, sandboxing, or whitelisting of allowed object types.
  - There is no fallback to a more secure serialization mechanism (for example, JSON) in production scenarios where untrusted data might be fed into the broker.
  **Preconditions:**
  - The attacker must be able to inject or modify messages in the broker (this may occur if a Redis, Disque, or similar message broker is misconfigured or publicly accessible).
  - The attacker must know, guess, or force the use of the proper signature (by compromising or brute‑forcing the SECRET_KEY), thereby making the malicious payload pass the signature check.
  **Source Code Analysis:**
  - In the file `django_q/signing.py` the project defines a `PickleSerializer` that directly wraps the built‑in `pickle.dumps` and `pickle.loads` functions without additional safeguards.
  - The method `SignedPackage.loads` (called, for example, in the task “pusher” routine in `django_q/cluster.py`) first verifies the signature and then immediately deserializes the payload with `pickle.loads`.
  - Test modules such as `test_cluster.py` illustrate that tasks are enqueued and later processed by worker routines that call these unsafe deserialization methods.
  **Security Test Case:**
  1. Deploy the application in a controlled test environment where the broker (for example, a Redis instance) is accessible without strong authentication.
  2. Configure the Django settings with a known or weak `SECRET_KEY`.
  3. Create a custom Python script that uses Python’s `pickle` module to construct a payload that, when deserialized, executes an arbitrary command (for example, running `os.system("touch /tmp/exploited")`).
  4. Sign this payload using the project’s signing function (e.g. via `SignedPackage.dumps`) so that it passes the signature check.
  5. Inject the crafted payload directly into the broker (for instance, using the Redis CLI).
  6. When a worker process retrieves the malicious task, verify (by checking for expected side effects such as file creation or log entries) that the payload executes and grants remote code execution.

- **Vulnerability Name:** Unsafe Use of Eval() in Schedule Parameter Parsing
  **Description:**
  The scheduler code expects schedule records to provide keyword arguments (in the `kwargs` field) as a string that can be converted into a dictionary. To perform this conversion, the project uses Python’s `eval()` function wrapped as:
  ```python
  if s.kwargs:
      try:
          kwargs = eval(f"dict({s.kwargs})")
      except SyntaxError:
          kwargs = {}
  ```
  Because `eval()` executes its input as arbitrary Python code, if an attacker can create or modify a schedule record—via a poorly secured Django admin interface or an exposed scheduling API—they can insert malicious Python code within the string. When the scheduler processes this record, the dangerous code within `s.kwargs` is executed.
  **Impact:**
  An attacker who successfully injects arbitrary Python code into the schedule’s `kwargs` can achieve remote code execution in the context of the scheduler. Depending on the privileges of the scheduler, this may allow full system compromise.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The code wraps the evaluation in a try/except block, such that if a `SyntaxError` is raised the schedule is processed with an empty dictionary.
  - It is assumed that schedule records are created exclusively by trusted administrators.
  **Missing Mitigations:**
  - Relying on `eval()` to convert unsanitized input remains inherently unsafe. A secure alternative such as Python’s `ast.literal_eval()` should be used to safely parse literals.
  - There is no active validation or sanitization of the string contained in `s.kwargs` before it is passed to `eval()`.
  **Preconditions:**
  - The attacker must be able to create or modify schedule records (for example, through an exposed admin interface or an unsecured scheduling API endpoint).
  - The scheduler must run and process the record containing the malicious `kwargs` string.
  **Source Code Analysis:**
  - In the scheduler routine (as evidenced by tests in `test_scheduler.py` and documented in the code comments), the schedule record’s `kwargs` is converted using `eval(f"dict({s.kwargs})")` without any restrictions.
  - This effectively means that any malicious payload inserted into the `kwargs` field will be executed in the Python runtime.
  **Security Test Case:**
  1. In a controlled environment, obtain access to the schedule creation interface (for example, via the Django admin or a scheduling API).
  2. Create a schedule record whose `kwargs` field is set to a malicious string. For instance, use a payload such as:
     ```
     "__import__('os').system('touch /tmp/exploited') or {}"
     ```
  3. Allow the scheduler to run so that it processes this schedule record.
  4. Verify that the injected command is executed by checking for its side‐effect (e.g., confirm that the file `/tmp/exploited` has been created).
  5. Demonstrate that replacing the unsafe `eval()` with a safer alternative (such as `ast.literal_eval()`) prevents the malicious code from executing.