```python
# Example of insecure authentication configuration (AVOID THIS)
from elasticsearch import Elasticsearch

# Hardcoded credentials - VERY BAD PRACTICE
es_insecure = Elasticsearch(
    cloud_id="YOUR_CLOUD_ID",
    api_key=("YOUR_API_KEY_ID", "YOUR_API_KEY_VALUE")
)

# Example of more secure authentication configuration (using environment variables)
import os
from elasticsearch import Elasticsearch

es_secure = Elasticsearch(
    cloud_id=os.environ.get("ELASTIC_CLOUD_ID"),
    api_key=(os.environ.get("ELASTIC_API_KEY_ID"), os.environ.get("ELASTIC_API_KEY_VALUE"))
)

# Even better: Using a secrets management solution (conceptual example)
# Assuming you have a 'secrets_manager' object from a library like 'hashicorp-vault'
# or 'aws-secretsmanager-sdk'
# from your_secrets_manager_library import SecretsManager

# secrets_manager = SecretsManager() # Initialize your secrets manager
# elastic_credentials = secrets_manager.get_secret("elastic-credentials")

# es_secrets = Elasticsearch(
#     cloud_id=elastic_credentials["cloud_id"],
#     api_key=(elastic_credentials["api_key_id"], elastic_credentials["api_key_value"])
# )
```
