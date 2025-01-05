```python
# This is a conceptual representation, actual implementation would vary based on the receiving application's language and framework.

# Example of signature verification in a receiving application (Python)
import hashlib
import hmac

def verify_webhook_signature(request_data, signature, secret):
    """Verifies the signature of a webhook request."""
    message = request_data.encode('utf-8')
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        message,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected_signature)

# Example usage (assuming Flask framework)
from flask import Flask, request, jsonify

app = Flask(__name__)

WEBHOOK_SECRET = "your_super_secret_key" # Should be securely stored

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    signature = request.headers.get('X-Webhook-Signature') # Assuming Kratos sends this header
    if not signature:
        return "Missing signature", 400

    request_data = request.get_data(as_text=True)

    if verify_webhook_signature(request_data, signature, WEBHOOK_SECRET):
        # Process the webhook data securely
        print("Webhook received and signature verified!")
        data = request.get_json()
        print("Webhook data:", data)
        # Perform actions based on the webhook data
        return jsonify({"status": "success"}), 200
    else:
        print("Invalid webhook signature!")
        return "Invalid signature", 401

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```