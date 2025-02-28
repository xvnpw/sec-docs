# Vulnerabilities in AI Toolkit for Visual Studio Code

## 1. Command Injection through Remote Model Endpoint

### Description
The AI Toolkit extension allows users to add remote models by providing a custom endpoint URL. When a malicious repository tricks a user into adding a specially crafted local endpoint URL (like `http://localhost:XXXX/exploit`), it could lead to command execution on the user's machine. The attacker controls this endpoint and when the user interacts with the model in the playground, the extension sends requests to this malicious endpoint which could return payloads designed to exploit command injection vulnerabilities in the extension's request handling.

### Impact
An attacker could execute arbitrary commands on the victim's machine with the same privileges as the VS Code process. This could lead to data theft, further system compromise, or lateral movement within the network.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The documentation doesn't indicate any specific validation or sanitization of the remote endpoint URLs beyond basic URL formatting.

### Missing Mitigations
- Lack of proper validation for remote endpoint URLs
- No warning to users about security implications of adding untrusted endpoints
- Absence of sandboxing for remote endpoint interactions

### Preconditions
1. The victim must have the AI Toolkit extension installed
2. The attacker must convince the victim to add a malicious endpoint URL
3. The victim must interact with the added model in the playground

### Source Code Analysis
While the exact implementation code isn't available in the provided files, we can infer from the documentation:

1. From `doc/playground.md`, the extension provides a way to add remote models:
   ```
   1. Click the "+" icon when hovering on "MODELS" tree view or enter `AI Toolkit: Add model for remote inference` in command palette.
   ```

2. Users provide model name, endpoint URL, and authentication header:
   ```
   3. Enter OpenAI compatible chat completion endpoint URL.
   4. If your endpoint requires authentication, you can set an authentication header for API key.
   ```

3. When a user interacts with the model in playground, the extension sends requests to this endpoint:
   ```
   5. After it is successfully added, the new model will appear in tree view, tagged with `Remote`. It will also appear in model drop down in playground. You can select the model in playground and try inference just like other local models.
   ```

4. The extension likely doesn't properly validate or sandbox these requests, allowing a malicious endpoint to potentially send back payloads that could trigger command injection in the extension's processing logic.

### Security Test Case
1. Set up a malicious endpoint locally (e.g., using Python's Flask framework) that serves a specially crafted response designed to inject commands
2. Create a GitHub repository with documentation guiding users to add this endpoint to AI Toolkit
3. When a victim adds the endpoint and interacts with the model in playground, the malicious endpoint returns a payload containing command injection attempts
4. The payload exploits the extension's request handling to execute arbitrary commands on the victim's machine
5. The attacker can verify successful command execution by having the commands exfiltrate data or connect back to a controlled server

## 2. Remote Code Execution via Model Loading

### Description
When loading models from external sources (such as GitHub or Hugging Face), the AI Toolkit extension might not properly validate the model files before execution. A malicious repository could provide a model that contains embedded code that executes when loaded by the extension.

### Impact
An attacker could execute arbitrary code on the user's machine, potentially leading to full system compromise, data theft, or installation of persistent malware.

### Vulnerability Rank
Critical

### Currently Implemented Mitigations
The documentation doesn't indicate any specific validation or sandboxing of loaded models.

### Missing Mitigations
- Lack of proper validation of model files before loading
- Absence of sandboxing for model execution
- No digital signature verification for downloaded models

### Preconditions
1. The victim must have the AI Toolkit extension installed
2. The victim must download and load a malicious model (either directly or through being pointed to a malicious repository)

### Source Code Analysis
Based on the documentation in `doc/models.md` and `archive/README.md`:

1. The extension allows downloading models from various sources:
   ```
   AI Toolkit supports a broad range of generative AI models. Both Small Language Models (SLM) and Large Language Models (LLM) are supported.
   ```

2. Models can be loaded from various sources including GitHub and Hugging Face:
   ```
   AI Toolkit now supports GitHub, ONNX, OpenAI, Anthropic, Google as model hosting sources.
   ```

3. The loading process seems to involve direct execution rather than sandboxed validation:
   ```
   On each model card, there are several options: 
   - **Try in Playground** link that can load selected model in playground for test without model downloading.
   - **Download** link that will download the model to local first from source like Hugging Face.
   - **Load in Playground** will load the downloaded model into playground for chat.
   ```

4. The extension likely loads these models for execution in a process with significant user privileges, allowing malicious code embedded in the model to execute.

### Security Test Case
1. Create a malicious model file with embedded code execution payload
2. Host this model on a repository or create a mock service that serves this model
3. Create a GitHub repository with documentation guiding users to download and load this specific model
4. When a victim downloads and loads the model, the embedded code executes
5. The malicious code can be designed to exfiltrate data or establish persistence on the victim's machine

## 3. Code Injection through Model Fine-tuning

### Description
The AI Toolkit supports model fine-tuning which involves executing script files from the project. If a victim is tricked into cloning a malicious repository that contains crafted fine-tuning scripts, these could lead to code injection when executed through the extension's fine-tuning feature.

### Impact
Successful exploitation would allow an attacker to execute arbitrary code on the victim's machine, potentially leading to data theft, installation of malware, or further system compromise.

### Vulnerability Rank
High

### Currently Implemented Mitigations
The documentation doesn't indicate any specific validation or sandboxing of fine-tuning scripts before execution.

### Missing Mitigations
- Lack of proper validation of fine-tuning script files
- Absence of sandboxing for script execution
- No warnings to users about the risks of running fine-tuning on untrusted repositories

### Preconditions
1. The victim must have the AI Toolkit extension installed
2. The victim must be convinced to clone and open a malicious repository
3. The victim must initiate the fine-tuning process on the malicious repository

### Source Code Analysis
From the documentation in `doc/finetune.md` and `archive/remote-finetuning.md`:

1. The extension supports fine-tuning models locally and remotely:
   ```
   Model fine-tuning in machine learning involves subtly adjusting an existing model, originally trained on a larger dataset, to perform a similar but new task using a smaller dataset.
   ```

2. The fine-tuning process involves executing commands:
   ```
   Upon running this command, the extension will do the following operations:
   1. Synchronize your workspace with Azure Files.
   1. Trigger the Azure Container Appjob using the commands specified in `./infra/fintuning.config.json`.
   ```

3. These commands are specified in configuration files which could be manipulated in a malicious repository:
   ```json
   "COMMANDS": [
     "cd /mount",
     "pip install huggingface-hub==0.22.2",
     "huggingface-cli download <your-model-name> --local-dir ./model-cache/<your-model-name> --local-dir-use-symlinks False",
     "pip install -r ./setup/requirements.txt",
     "python3 ./finetuning/invoke_olive.py && find models/ -print | grep adapter/adapter"
   ]
   ```

4. The extension likely executes these commands without proper validation, allowing for code injection through malicious commands in the configuration files.

### Security Test Case
1. Create a malicious repository with modified `finetuning.config.json` containing injected commands
2. The injected commands could contain malicious Python scripts or direct shell commands
3. Guide the victim to clone this repository and start the fine-tuning process
4. When the victim initiates fine-tuning, the malicious commands execute
5. The commands can be designed to exfiltrate data or establish persistence