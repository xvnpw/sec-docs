```python
# This is a conceptual Python code snippet to illustrate monitoring framework registration events.
# It would need to be adapted to integrate with the actual Mesos event stream.

import time
import json

# Placeholder for fetching Mesos events (replace with actual Mesos API interaction)
def get_mesos_events():
    # In a real scenario, this would query the Mesos Master's event stream.
    # For demonstration, we'll simulate some events.
    return [
        {"type": "FRAMEWORK_ADDED", "framework_id": "legitimate-framework-1", "user": "devops", "name": "Legit App"},
        {"type": "FRAMEWORK_ADDED", "framework_id": "attacker-impersonation", "user": "attacker", "name": "Malicious Framework"},
        {"type": "FRAMEWORK_ADDED", "framework_id": "legitimate-framework-1", "user": "attacker", "name": "Legit App"}, # Suspicious!
        {"type": "FRAMEWORK_ADDED", "framework_added_event": {"framework": {"id": {"value": "another-legit-framework"}}}, "user": "devops", "name": "Another App"},
    ]

def analyze_framework_registrations(events):
    registered_frameworks = {}
    suspicious_activities = []

    for event in events:
        if event.get("type") == "FRAMEWORK_ADDED" or event.get("framework_added_event"):
            framework_id = event.get("framework_id") or event.get("framework_added_event", {}).get("framework", {}).get("id", {}).get("value")
            user = event.get("user")
            name = event.get("name")

            if framework_id:
                if framework_id not in registered_frameworks:
                    registered_frameworks[framework_id] = {"first_seen_user": user, "names": [name]}
                else:
                    # Suspicion 1: Different user registering with the same ID
                    if registered_frameworks[framework_id]["first_seen_user"] != user:
                        suspicious_activities.append(f"Suspicious registration: Framework ID '{framework_id}' registered by user '{user}', previously seen by '{registered_frameworks[framework_id]['first_seen_user']}'.")
                    # Suspicion 2: Different name for the same ID (less critical, but worth noting)
                    if name not in registered_frameworks[framework_id]["names"]:
                        registered_frameworks[framework_id]["names"].append(name)
                        suspicious_activities.append(f"Framework ID '{framework_id}' registered with a new name: '{name}'. Previous names: {registered_frameworks[framework_id]['names'][:-1]}.")

    return suspicious_activities

if __name__ == "__main__":
    print("Monitoring Mesos framework registrations for suspicious activity...")
    while True:
        events = get_mesos_events() # Replace with actual event fetching
        suspicious = analyze_framework_registrations(events)
        if suspicious:
            print("\n--- SUSPICIOUS ACTIVITY DETECTED ---")
            for activity in suspicious:
                print(activity)
            print("-----------------------------------\n")

        time.sleep(5) # Check for new events periodically
```