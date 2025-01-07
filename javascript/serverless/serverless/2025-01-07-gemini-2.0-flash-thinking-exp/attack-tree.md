# Attack Tree Analysis for serverless/serverless

Objective: Compromise Serverless Application

## Attack Tree Visualization

```
* Compromise Serverless Application
    * Gain Unauthorized Access to Sensitive Data [CRITICAL NODE]
        * Exploit Function Code Vulnerabilities (Serverless Specific) [CRITICAL NODE]
        * Exploit Misconfigured IAM Roles (Serverless Specific) [CRITICAL NODE]
            * Overly Permissive Function Role [HIGH RISK PATH]
        * Compromise Environment Variables Containing Secrets (Serverless Specific) [CRITICAL NODE]
            * Accessing Environment Variables through Code Vulnerabilities [HIGH RISK PATH]
            * Exploiting Insecure Secrets Management Practices [HIGH RISK PATH]
        * Exploit Vulnerabilities in Integrated Services (Indirectly Serverless)
            * Exploit Vulnerabilities in Storage Services (e.g., S3) [HIGH RISK PATH]
    * Disrupt Application Availability (Denial of Service - Serverless Specific) [CRITICAL NODE]
        * Trigger Excessive Function Invocations (Cost DoS) [CRITICAL NODE]
            * Exploiting Publicly Accessible API Gateway Endpoints [HIGH RISK PATH]
            * Exploiting Lack of Rate Limiting or Throttling [HIGH RISK PATH]
        * Exploit API Gateway Vulnerabilities (Serverless Entry Point) [CRITICAL NODE]
            * Overwhelming API Gateway with Requests [HIGH RISK PATH]
            * Exploiting Missing or Weak Authentication/Authorization at API Gateway [HIGH RISK PATH]
    * Hijack Application Resources for Malicious Purposes (Serverless Specific) [CRITICAL NODE]
        * Exploit Function Code Vulnerabilities for Resource Abuse [CRITICAL NODE]
            * Data Exfiltration through Function's Network Access [HIGH RISK PATH]
        * Compromise Deployment Pipeline to Inject Malicious Code (Serverless Specific) [CRITICAL NODE]
            * Compromise CI/CD Pipeline Credentials [HIGH RISK PATH]
            * Inject Malicious Code into Deployment Artifacts [HIGH RISK PATH]
            * Backdoor Function Code During Deployment [HIGH RISK PATH]
        * Exploit Misconfigured IAM Roles for Resource Access [CRITICAL NODE]
            * Using Overly Permissive Roles to Access and Control Other Resources [HIGH RISK PATH]
```


## Attack Tree Path: [Gain Unauthorized Access to Sensitive Data [CRITICAL NODE]](./attack_tree_paths/gain_unauthorized_access_to_sensitive_data__critical_node_.md)

* This represents the overarching goal of accessing data the attacker is not authorized to view.
    * Exploit Function Code Vulnerabilities (Serverless Specific) [CRITICAL NODE]
        * **Attack Vectors:**
            * Function Logic Flaws Leading to Data Exposure: Exploiting errors in the code's logic that unintentionally reveal sensitive information.
            * Insecure Deserialization in Function Handlers:  Manipulating serialized data sent to the function to execute arbitrary code or access data.
            * Server-Side Request Forgery (SSRF) from within Function:  Using the function's ability to make external requests to access internal resources or services.
    * Exploit Misconfigured IAM Roles (Serverless Specific) [CRITICAL NODE]
        * **Attack Vectors:**
            * Overly Permissive Function Role [HIGH RISK PATH]: The function's IAM role grants it more permissions than necessary, allowing access to sensitive data or resources it shouldn't have.
    * Compromise Environment Variables Containing Secrets (Serverless Specific) [CRITICAL NODE]
        * **Attack Vectors:**
            * Accessing Environment Variables through Code Vulnerabilities [HIGH RISK PATH]: Exploiting vulnerabilities like path traversal or command injection within the function code to read the environment variables.
            * Exploiting Insecure Secrets Management Practices [HIGH RISK PATH]:  Directly accessing secrets if they are stored insecurely in environment variables without encryption or proper management.
    * Exploit Vulnerabilities in Integrated Services (Indirectly Serverless)
        * **Attack Vectors:**
            * Exploit Vulnerabilities in Storage Services (e.g., S3) [HIGH RISK PATH]:  Leveraging misconfigurations or vulnerabilities in storage services like S3 to access sensitive data stored there.

## Attack Tree Path: [Disrupt Application Availability (Denial of Service - Serverless Specific) [CRITICAL NODE]](./attack_tree_paths/disrupt_application_availability__denial_of_service_-_serverless_specific___critical_node_.md)

* This aims to make the application unavailable to legitimate users.
    * Trigger Excessive Function Invocations (Cost DoS) [CRITICAL NODE]
        * **Attack Vectors:**
            * Exploiting Publicly Accessible API Gateway Endpoints [HIGH RISK PATH]: Flooding publicly accessible API endpoints with requests, triggering a massive number of function invocations.
            * Exploiting Lack of Rate Limiting or Throttling [HIGH RISK PATH]:  Sending a large volume of requests to API endpoints without any restrictions, overwhelming the system.
    * Exploit API Gateway Vulnerabilities (Serverless Entry Point) [CRITICAL NODE]
        * **Attack Vectors:**
            * Overwhelming API Gateway with Requests [HIGH RISK PATH]: Sending a large number of requests to saturate the API Gateway's capacity, making it unresponsive.
            * Exploiting Missing or Weak Authentication/Authorization at API Gateway [HIGH RISK PATH]: Bypassing or exploiting weaknesses in the API Gateway's authentication or authorization mechanisms to send unauthorized requests.

## Attack Tree Path: [Hijack Application Resources for Malicious Purposes (Serverless Specific) [CRITICAL NODE]](./attack_tree_paths/hijack_application_resources_for_malicious_purposes__serverless_specific___critical_node_.md)

* This involves taking control of the application's resources to perform malicious activities.
    * Exploit Function Code Vulnerabilities for Resource Abuse [CRITICAL NODE]
        * **Attack Vectors:**
            * Data Exfiltration through Function's Network Access [HIGH RISK PATH]: Using the function's ability to make network requests to send stolen data to attacker-controlled locations.
    * Compromise Deployment Pipeline to Inject Malicious Code (Serverless Specific) [CRITICAL NODE]
        * **Attack Vectors:**
            * Compromise CI/CD Pipeline Credentials [HIGH RISK PATH]: Gaining access to the credentials used by the Continuous Integration/Continuous Deployment pipeline to deploy code.
            * Inject Malicious Code into Deployment Artifacts [HIGH RISK PATH]: Modifying the code or configuration files being deployed to include malicious functionality.
            * Backdoor Function Code During Deployment [HIGH RISK PATH]: Introducing backdoors into the function code during the deployment process, allowing for persistent unauthorized access.
    * Exploit Misconfigured IAM Roles for Resource Access [CRITICAL NODE]
        * **Attack Vectors:**
            * Using Overly Permissive Roles to Access and Control Other Resources [HIGH RISK PATH]: Leveraging excessive permissions granted to the function's role to access and manipulate other AWS resources beyond its intended scope.

