# BUSINESS POSTURE

ToolJet is an open-source low-code platform designed to enable businesses to rapidly build and deploy internal tools. The primary business priority is to empower organizations to create custom applications and workflows without extensive coding, thereby increasing operational efficiency and reducing development costs.

Key business goals include:

- Accelerate internal tool development: Reduce the time and resources required to build internal applications.
- Empower non-technical users: Enable citizen developers to contribute to tool creation and customization.
- Improve operational efficiency: Streamline internal processes and workflows through custom-built applications.
- Reduce software development costs: Lower reliance on large development teams for internal tool development.
- Enhance data accessibility and utilization: Connect to various data sources and make data readily available for internal operations.

Most important business risks to address:

- Data breaches and unauthorized access: Internal tools often handle sensitive business data, making data security paramount.
- Service disruption and availability:  The platform needs to be reliable and available to ensure business continuity for critical internal processes.
- Data integrity and accuracy:  Tools must process and present data accurately to avoid flawed decision-making.
- Vendor lock-in (for hosted versions): If a hosted version is offered, avoid dependencies that could lead to lock-in and hinder future flexibility.
- Compliance and regulatory risks: Depending on the industry and data handled, compliance with regulations (e.g., GDPR, HIPAA) is crucial.

# SECURITY POSTURE

Existing security controls:

- security control: Open-source nature allows for community review and identification of vulnerabilities (described in project's open-source model).
- security control: Standard web application security practices are likely followed (assumption based on typical web application development).
- security control: Input validation and sanitization are likely implemented to prevent common web vulnerabilities (assumption based on typical web application development).
- security control: Authentication and authorization mechanisms are likely in place to manage user access (assumption based on platform functionality).
- security control: Secure coding practices are likely followed by the development team (assumption based on project maturity and community).

Accepted risks:

- accepted risk: Reliance on community contributions for security vulnerability identification and patching.
- accepted risk: Potential for vulnerabilities to exist in dependencies and third-party libraries.
- accepted risk: Security configurations might not be hardened by default and require user configuration.
- accepted risk:  Security awareness and secure usage practices might vary among users building and using tools.

Recommended security controls:

- security control: Implement automated security scanning tools (SAST, DAST, dependency scanning) in the CI/CD pipeline.
- security control: Conduct regular penetration testing and security audits by external security experts.
- security control: Establish a formal vulnerability disclosure and incident response process.
- security control: Provide security training and guidance for users on secure tool development and usage practices.
- security control: Implement robust logging and monitoring for security events and anomalies.
- security control: Enforce strong password policies and multi-factor authentication.
- security control: Implement data encryption at rest and in transit for sensitive data.
- security control: Regularly update dependencies and libraries to patch known vulnerabilities.

Security requirements:

- Authentication:
    - requirement: Secure user authentication mechanisms to verify user identity.
    - requirement: Support for different authentication methods (e.g., username/password, SSO, OAuth).
    - requirement: Protection against brute-force attacks and account takeover.
- Authorization:
    - requirement: Role-based access control (RBAC) to manage user permissions and access to resources.
    - requirement: Granular authorization policies to control access to specific features and data.
    - requirement: Principle of least privilege should be enforced.
- Input Validation:
    - requirement: Comprehensive input validation on all user inputs to prevent injection attacks (e.g., SQL injection, XSS).
    - requirement: Input sanitization and encoding to neutralize malicious input.
    - requirement: Use of secure coding practices to handle user input safely.
- Cryptography:
    - requirement: Encryption of sensitive data at rest (e.g., database encryption).
    - requirement: Encryption of data in transit (HTTPS for web traffic).
    - requirement: Secure storage and management of cryptographic keys.
    - requirement: Use of strong and up-to-date cryptographic algorithms and libraries.

# DESIGN

## C4 CONTEXT

```mermaid
flowchart LR
    subgraph "Organization"
    U["Internal User"]
    end
    SystemBoundary(S)["ToolJet Platform"]
    D["Databases"]
    A["APIs & Services"]

    U -->|Uses| S
    S -->|Connects to| D
    S -->|Integrates with| A
    S -->|Provides data to| U

    style SystemBoundary fill:#f9f,stroke:#333,stroke-width:2px
```

Context Diagram Elements:

- Element:
    - Name: Internal User
    - Type: Person
    - Description: Employees within the organization who will use the ToolJet platform to build and utilize internal tools. This includes citizen developers, business users, and potentially IT administrators.
    - Responsibilities: Building, customizing, and using internal tools created on the ToolJet platform to improve their workflows and access data.
    - Security controls: User authentication to access the platform, authorization controls to access specific tools and data, adherence to secure usage guidelines.

- Element:
    - Name: ToolJet Platform
    - Type: System
    - Description: The ToolJet open-source low-code platform itself. It provides the environment and tools for users to build, deploy, and run internal applications.
    - Responsibilities: Providing a platform for building and running internal tools, managing user access and permissions, connecting to data sources, and ensuring platform availability and security.
    - Security controls: Authentication, authorization, input validation, data encryption, security logging and monitoring, secure software development lifecycle, regular security updates.

- Element:
    - Name: Databases
    - Type: External System
    - Description: Various databases (e.g., PostgreSQL, MySQL, MongoDB, cloud databases) that ToolJet connects to as data sources for internal tools. These databases contain organizational data that internal tools need to access and manipulate.
    - Responsibilities: Storing and providing access to organizational data. Ensuring data integrity, availability, and security.
    - Security controls: Database access controls, encryption at rest, data backups, database monitoring, vulnerability management.

- Element:
    - Name: APIs & Services
    - Type: External System
    - Description: External APIs and services (e.g., REST APIs, SaaS applications, cloud services) that ToolJet integrates with to extend the functionality of internal tools or access external data.
    - Responsibilities: Providing external functionalities and data to ToolJet applications. Ensuring API availability, security, and data integrity.
    - Security controls: API authentication and authorization, secure API communication (HTTPS), input validation, rate limiting, API monitoring.

## C4 CONTAINER

```mermaid
flowchart LR
    subgraph "ToolJet Platform"
    subgraph "Web Application"
    FE["Frontend (React)"]
    BE["Backend API (Node.js)"]
    end
    DB["Database (PostgreSQL)"]
    WQ["Workflow Queue (Redis)"]
    WE["Workflow Engine (Node.js)"]
    AC["Admin Console (React)"]
    end

    U["Internal User"] -->|Uses Web Browser| FE
    FE -->|API Calls (HTTPS)| BE
    BE -->|Queries (JDBC/ORM)| DB
    BE -->|Publishes Tasks| WQ
    WE -->|Subscribes to Tasks| WQ
    WE -->|Executes Workflows, Connects to Data Sources, APIs| BE
    U -->|Uses Web Browser| AC
    AC -->|API Calls (HTTPS)| BE

    style "ToolJet Platform" fill:#ccf,stroke:#333,stroke-width:2px
    style "Web Application" fill:#eee,stroke:#333,stroke-width:1px
```

Container Diagram Elements:

- Element:
    - Name: Frontend (React)
    - Type: Container
    - Description: The client-side web application built with React. It provides the user interface for building and interacting with internal tools. Served to users' browsers.
    - Responsibilities: Rendering user interface, handling user interactions, making API calls to the Backend API, managing application state in the browser.
    - Security controls: Input validation on the client-side, secure handling of user sessions, protection against client-side vulnerabilities (e.g., XSS), Content Security Policy (CSP).

- Element:
    - Name: Backend API (Node.js)
    - Type: Container
    - Description: The server-side application built with Node.js. It exposes REST APIs for the Frontend and Admin Console to interact with. Handles business logic, data access, and workflow orchestration.
    - Responsibilities: API endpoint management, authentication and authorization, business logic execution, data validation and processing, database interactions, workflow management, integration with external systems.
    - Security controls: Authentication, authorization, input validation, secure API design, protection against server-side vulnerabilities (e.g., injection attacks), rate limiting, API security logging and monitoring.

- Element:
    - Name: Database (PostgreSQL)
    - Type: Container
    - Description: The relational database used for persistent storage of application data, including user data, tool definitions, configurations, and workflow states. PostgreSQL is chosen as an example, other databases might be supported.
    - Responsibilities: Persistent data storage, data retrieval, data integrity, data backups, database performance and availability.
    - Security controls: Database access controls, database user management, encryption at rest, regular backups, database monitoring, vulnerability patching.

- Element:
    - Name: Workflow Queue (Redis)
    - Type: Container
    - Description: A message queue system (Redis is used as an example) for asynchronous task processing. It decouples the Backend API from long-running workflow executions, improving responsiveness and scalability.
    - Responsibilities: Queueing workflow tasks, message delivery, task persistence (optional), enabling asynchronous processing.
    - Security controls: Access control to the queue, secure communication within the queue system, monitoring of queue activity.

- Element:
    - Name: Workflow Engine (Node.js)
    - Type: Container
    - Description: A dedicated service responsible for executing workflows defined in ToolJet. It subscribes to tasks from the Workflow Queue, executes workflow steps, and interacts with data sources and APIs as needed.
    - Responsibilities: Workflow execution, workflow state management, interaction with data sources and APIs, error handling, logging of workflow execution.
    - Security controls: Secure workflow execution environment, authorization for accessing data sources and APIs, input validation within workflows, logging and monitoring of workflow activities.

- Element:
    - Name: Admin Console (React)
    - Type: Container
    - Description: A separate frontend application, likely built with React, providing administrative functionalities for managing the ToolJet platform itself. This could include user management, configuration settings, monitoring, etc.
    - Responsibilities: Platform administration, user management, configuration management, monitoring and logging access, platform health checks.
    - Security controls: Authentication and authorization (separate from regular user access, likely requiring higher privileges), audit logging of administrative actions, secure configuration management.

## DEPLOYMENT

Deployment Architecture: Cloud Deployment (AWS - Example)

```mermaid
flowchart LR
    subgraph "AWS Cloud"
    subgraph "VPC"
    subgraph "Public Subnet"
    LB["Load Balancer (ALB)"]
    end
    subgraph "Private Subnet"
    ASG_WEB["Web Application ASG"]
    WEB_INSTANCE_1["Web Instance 1"]
    WEB_INSTANCE_2["Web Instance 2"]
    ASG_WORKFLOW["Workflow Engine ASG"]
    WORKFLOW_INSTANCE_1["Workflow Instance 1"]
    WORKFLOW_INSTANCE_2["Workflow Instance 2"]
    DB_RDS["RDS PostgreSQL"]
    CACHE_ElastiCache["ElastiCache Redis"]
    end
    end

    Internet["Internet"] --> LB
    LB --> ASG_WEB
    ASG_WEB --> WEB_INSTANCE_1
    ASG_WEB --> WEB_INSTANCE_2
    WEB_INSTANCE_1 --> DB_RDS
    WEB_INSTANCE_2 --> DB_RDS
    WEB_INSTANCE_1 --> CACHE_ElastiCache
    WEB_INSTANCE_2 --> CACHE_ElastiCache
    ASG_WORKFLOW --> WORKFLOW_INSTANCE_1
    ASG_WORKFLOW --> WORKFLOW_INSTANCE_2
    WORKFLOW_INSTANCE_1 --> DB_RDS
    WORKFLOW_INSTANCE_2 --> DB_RDS
    WORKFLOW_INSTANCE_1 --> CACHE_ElastiCache
    WORKFLOW_INSTANCE_2 --> CACHE_ElastiCache
    WEB_INSTANCE_1 --> CACHE_ElastiCache
    WEB_INSTANCE_2 --> CACHE_ElastiCache

    style "AWS Cloud" fill:#eef,stroke:#333,stroke-width:2px
    style "VPC" fill:#eee,stroke:#333,stroke-width:1px
    style "Public Subnet" fill:#fef,stroke:#333,stroke-width:1px
    style "Private Subnet" fill:#fef,stroke:#333,stroke-width:1px
```

Deployment Diagram Elements (AWS Example):

- Element:
    - Name: Internet
    - Type: Environment
    - Description: The public internet, representing users accessing the ToolJet platform from outside the AWS environment.
    - Responsibilities: Providing network connectivity for users to access the platform.
    - Security controls: None directly controlled by ToolJet deployment, relies on standard internet security protocols and user-side security.

- Element:
    - Name: Load Balancer (ALB)
    - Type: Infrastructure
    - Description: AWS Application Load Balancer (ALB) in a public subnet. Distributes incoming traffic across web application instances and provides SSL termination.
    - Responsibilities: Traffic distribution, load balancing, SSL termination, routing requests to healthy instances.
    - Security controls: SSL/TLS encryption, security groups to control inbound traffic, DDoS protection (AWS Shield), access logging.

- Element:
    - Name: Web Application ASG
    - Type: Infrastructure
    - Description: AWS Auto Scaling Group (ASG) for the Web Application (Frontend and Backend API containers). Ensures high availability and scalability of the web application. Deployed in private subnets.
    - Responsibilities: Automatic scaling of web application instances based on load, health checks, instance management.
    - Security controls: Security groups to control inbound and outbound traffic, IAM roles for instance permissions, regular patching of instances.

- Element:
    - Name: Web Instance (EC2)
    - Type: Infrastructure
    - Description: EC2 instances within the Web Application ASG, running the Frontend and Backend API containers (likely using Docker).
    - Responsibilities: Running the Web Application containers, serving user requests, interacting with the database and cache.
    - Security controls: Instance hardening, OS patching, container security, application-level security controls.

- Element:
    - Name: Workflow Engine ASG
    - Type: Infrastructure
    - Description: AWS Auto Scaling Group (ASG) for the Workflow Engine containers. Ensures high availability and scalability of the workflow processing. Deployed in private subnets.
    - Responsibilities: Automatic scaling of workflow engine instances, processing workflow tasks from the queue.
    - Security controls: Security groups, IAM roles, instance hardening, OS patching, container security, application-level security controls.

- Element:
    - Name: Workflow Instance (EC2)
    - Type: Infrastructure
    - Description: EC2 instances within the Workflow Engine ASG, running the Workflow Engine containers (likely using Docker).
    - Responsibilities: Running Workflow Engine containers, executing workflow tasks, interacting with database, cache, and external services.
    - Security controls: Instance hardening, OS patching, container security, application-level security controls.

- Element:
    - Name: RDS PostgreSQL
    - Type: PaaS
    - Description: AWS RDS (Relational Database Service) for PostgreSQL. Managed database service providing scalability, availability, and security. Deployed in private subnets.
    - Responsibilities: Managed database service, persistent data storage, backups, high availability, database management.
    - Security controls: VPC security groups, database access controls, encryption at rest and in transit, automated backups, database monitoring, patching managed by AWS.

- Element:
    - Name: ElastiCache Redis
    - Type: PaaS
    - Description: AWS ElastiCache for Redis. Managed in-memory data store service used as a workflow queue and potentially for caching. Deployed in private subnets.
    - Responsibilities: Managed cache and message queue service, fast data access, message queuing, scalability, availability.
    - Security controls: VPC security groups, access control lists (ACLs), encryption in transit, data persistence options, monitoring, patching managed by AWS.

## BUILD

```mermaid
flowchart LR
    Developer["Developer"] -->|Code Commit| VCS["Version Control System (GitHub)"]
    VCS -->|Webhook| CI["CI Server (GitHub Actions)"]
    CI -->|Build & Test| BUILD_PROCESS["Build Process"]
    BUILD_PROCESS -->|Security Scans (SAST, Dependency Check)| SECURITY_SCANS["Security Scans"]
    SECURITY_SCANS -->|Artifacts & Reports| ARTIFACT_REPO["Artifact Repository"]
    ARTIFACT_REPO -->|Deployment| DEPLOYMENT_ENV["Deployment Environment"]

    subgraph "Build Process"
    BUILD_STEPS["Build Steps:\n- Code Checkout\n- Dependency Install\n- Compile\n- Unit Tests\n- Package"]
    end
    BUILD_PROCESS --> BUILD_STEPS

    style "Build Process" fill:#eee,stroke:#333,stroke-width:1px
```

Build Process Description:

The build process for ToolJet is likely automated using a CI/CD system like GitHub Actions, given it's hosted on GitHub.

Build Process Elements:

- Element:
    - Name: Developer
    - Type: Person
    - Description: Software developers contributing code to the ToolJet project.
    - Responsibilities: Writing code, committing code changes, performing local testing.
    - Security controls: Secure development environment, code review practices, adherence to secure coding guidelines.

- Element:
    - Name: Version Control System (GitHub)
    - Type: Tool
    - Description: GitHub repository hosting the ToolJet source code.
    - Responsibilities: Source code management, version control, collaboration, code review workflows.
    - Security controls: Access control to the repository, branch protection rules, audit logging of code changes, vulnerability scanning of repository configurations.

- Element:
    - Name: CI Server (GitHub Actions)
    - Type: Tool
    - Description: GitHub Actions used for continuous integration and continuous delivery. Automates the build, test, and deployment pipeline.
    - Responsibilities: Automated build execution, test automation, security scan execution, artifact creation, deployment automation.
    - Security controls: Secure CI/CD pipeline configuration, access control to CI/CD workflows, secret management for credentials, audit logging of CI/CD activities.

- Element:
    - Name: Build Process
    - Type: Process
    - Description: Automated steps involved in compiling, testing, and packaging the ToolJet application. Includes steps like code checkout, dependency installation, compilation, unit testing, and packaging into deployable artifacts (e.g., Docker images, binaries).
    - Responsibilities: Building the application from source code, running automated tests, creating deployable artifacts.
    - Security controls: Secure build environment, dependency management, build process hardening, integrity checks of build artifacts.

- Element:
    - Name: Security Scans
    - Type: Process
    - Description: Automated security scans integrated into the build process. Includes SAST (Static Application Security Testing) to analyze source code for vulnerabilities and dependency checking to identify vulnerable dependencies. DAST (Dynamic Application Security Testing) might be included in later stages or separate pipelines.
    - Responsibilities: Identifying potential security vulnerabilities in the code and dependencies early in the development lifecycle.
    - Security controls: SAST tools, dependency scanning tools, vulnerability reporting, integration with vulnerability management systems.

- Element:
    - Name: Artifact Repository
    - Type: Tool
    - Description: Repository for storing build artifacts, such as Docker images or binaries. Could be a container registry (e.g., Docker Hub, AWS ECR) or a binary repository.
    - Responsibilities: Secure storage of build artifacts, versioning of artifacts, access control to artifacts.
    - Security controls: Access control to the repository, vulnerability scanning of stored artifacts, integrity checks of artifacts, audit logging of artifact access.

- Element:
    - Name: Deployment Environment
    - Type: Environment
    - Description: Target environment where ToolJet is deployed (e.g., AWS Cloud, Kubernetes cluster, on-premises servers).
    - Responsibilities: Running the ToolJet application, providing runtime environment, infrastructure management.
    - Security controls: Deployment environment security controls as described in the DEPLOYMENT section.

# RISK ASSESSMENT

Critical business processes we are trying to protect:

- Building and deploying internal tools: The core functionality of ToolJet itself. Disruption would prevent users from creating or updating tools.
- Running internal tools:  The execution of deployed tools that automate business processes. Disruption would impact business operations relying on these tools.
- Accessing and processing business data: Internal tools connect to and process sensitive business data. Data breaches or data integrity issues could have significant business impact.
- User management and access control: Managing user accounts and permissions to ensure only authorized users can access and modify tools and data. Compromise could lead to unauthorized access and data breaches.

Data we are trying to protect and their sensitivity:

- User credentials: Usernames, passwords, API keys, authentication tokens. Highly sensitive, compromise leads to unauthorized access.
- Tool definitions and configurations:  Definitions of internal tools, workflows, data source connections, API configurations. Sensitive, compromise could lead to tool manipulation or data exposure.
- Business data accessed and processed by tools: Data from connected databases and APIs. Sensitivity depends on the nature of the data (e.g., customer data, financial data, operational data). Can range from confidential to highly sensitive, requiring appropriate protection based on data classification.
- Audit logs and security logs: Logs containing information about user activity, system events, and security events. Sensitive, can be used for security monitoring and incident response, but also contain potentially sensitive information.

# QUESTIONS & ASSUMPTIONS

Questions:

- What specific types of data sources and APIs does ToolJet primarily integrate with? (e.g., specific databases, SaaS platforms).
- What are the typical use cases and industries targeted by ToolJet? (e.g., internal dashboards, workflow automation, data management).
- Are there any specific compliance requirements that ToolJet needs to adhere to (e.g., GDPR, HIPAA, SOC 2)?
- What is the intended deployment model for ToolJet? (e.g., self-hosted, cloud-hosted, hybrid).
- What security features are currently implemented in ToolJet beyond standard web application security practices?
- Is there a formal security development lifecycle (SDL) followed by the ToolJet development team?
- Are there any existing penetration testing or security audit reports available for review?

Assumptions:

- ToolJet is primarily used for building internal tools within organizations.
- Security is a significant concern for organizations using low-code platforms for internal applications.
- ToolJet aims to provide a secure platform for building and running internal tools.
- Standard web application security best practices are generally followed in the development of ToolJet.
- Deployment is likely to be in cloud environments or on-premises data centers.
- Users of ToolJet will have varying levels of technical expertise and security awareness.