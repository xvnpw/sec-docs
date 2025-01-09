```python
# This is a conceptual example to illustrate the vulnerability, not a fully runnable Celery application.

from celery import Celery

app = Celery('tasks', broker='redis://localhost:6379/0')

# Vulnerable code: Dynamically generating task names based on untrusted input
def enqueue_task(user_input):
    task_name = f"process_{user_input}"
    # In a real application, you would enqueue the task here using app.send_task(task_name, ...)
    print(f"Enqueuing task with name: {task_name}")
    return task_name

# Example of how an attacker might exploit this
malicious_input = "__import__('os').system('touch /tmp/pwned')"
vulnerable_task_name = enqueue_task(malicious_input)

# In a real scenario, the Celery worker would attempt to import and execute this task name.
# This is a simplified representation of what happens internally in Celery.
try:
    # Celery internally uses something similar to this to load the task
    __import__(vulnerable_task_name)
except Exception as e:
    print(f"Error during (simulated) task import: {e}")

# --- Mitigation Examples ---

# Mitigation 1: Using a predefined, static set of task names
ALLOWED_TASKS = {"process_order", "update_inventory", "send_email"}

def enqueue_task_safe(task_type, data):
    if task_type in ALLOWED_TASKS:
        task_name = task_type
        # Enqueue the task with the predefined name and pass data as arguments
        # app.send_task(task_name, data)
        print(f"Enqueuing safe task: {task_name} with data: {data}")
    else:
        print(f"Invalid task type: {task_type}")

enqueue_task_safe("process_order", {"order_id": 123})
enqueue_task_safe("evil_task", {}) # This would be rejected

# Mitigation 2: Strict input validation (if dynamic generation is absolutely necessary)
import re

def enqueue_task_validated(user_input):
    # Define a strict pattern for valid task name components
    if re.match(r"^[a-zA-Z0-9_]+$", user_input):
        task_name = f"process_{user_input}"
        # Enqueue the task
        # app.send_task(task_name, ...)
        print(f"Enqueuing validated task: {task_name}")
        return task_name
    else:
        print(f"Invalid task name input: {user_input}")
        return None

enqueue_task_validated("order_123")
enqueue_task_validated("malicious;code") # This would be rejected
```