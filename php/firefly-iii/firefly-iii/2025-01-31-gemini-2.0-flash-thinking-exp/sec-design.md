# BUSINESS POSTURE

- Business priorities and goals:
 - Goal: Provide users with a self-hosted personal finance management solution.
 - Priority: User data privacy and security due to the sensitive nature of financial information.
 - Priority: Ease of use and accessibility for personal users.
 - Priority: Extensibility and customization to cater to diverse user needs.
 - Priority: Community support and open-source development.

- Most important business risks:
 - Risk: Data breaches and unauthorized access to user financial data, leading to reputational damage and loss of user trust.
 - Risk: Service unavailability due to technical issues or cyberattacks, disrupting user access to their financial information.
 - Risk: Data integrity issues, such as data corruption or loss, leading to inaccurate financial records.
 - Risk: Compliance risks related to data privacy regulations (e.g., GDPR, CCPA) if users are located in regions with such regulations.
 - Risk: Vulnerabilities in third-party dependencies, potentially compromising the security of the application.

# SECURITY POSTURE

- Existing security controls:
 - security control: HTTPS encryption for communication between user browsers and the application server. Implemented in web server configuration.
 - security control: Password hashing for user credentials. Implemented in application code.
 - security control: Input validation to prevent common web vulnerabilities. Implemented in application code.
 - security control: Protection against Cross-Site Scripting (XSS) attacks. Implemented in application code using templating engine and output encoding.
 - security control: Protection against Cross-Site Request Forgery (CSRF) attacks. Implemented in application code using CSRF tokens.
 - security control: Regular software updates for the application and underlying operating system. Described in documentation as a user responsibility.
 - security control: Database backups. Described in documentation as a user responsibility.
 - security control: Security headers (e.g., Content-Security-Policy, X-Frame-Options). Configurable in web server configuration.

- Accepted risks:
 - accepted risk: Self-hosting model places security responsibility on the user, who may lack security expertise.
 - accepted risk: Reliance on user-configured infrastructure for security measures like firewalls and intrusion detection systems.
 - accepted risk: Potential vulnerabilities in third-party dependencies that are not immediately patched.
 - accepted risk: Users might choose weak passwords, despite password complexity requirements.

- Recommended security controls:
 - security control: Implement Content Security Policy (CSP) to mitigate XSS attacks.
 - security control: Regularly scan dependencies for known vulnerabilities using tools like Dependabot or similar.
 - security control: Implement rate limiting to protect against brute-force attacks on login and other sensitive endpoints.
 - security control: Encourage users to enable Multi-Factor Authentication (MFA) for enhanced account security.
 - security control: Provide security hardening guides for common deployment environments (e.g., Docker, Linux servers).
 - security control: Implement automated security testing (SAST/DAST) in the development pipeline.

- Security requirements:
 - Authentication:
  - Requirement: Securely authenticate users accessing the application.
  - Requirement: Support strong password policies and encourage users to choose strong passwords.
  - Requirement: Consider implementing Multi-Factor Authentication (MFA) as an optional security enhancement.
  - Requirement: Implement session management to securely track user sessions and prevent session hijacking.
 - Authorization:
  - Requirement: Implement role-based access control to manage user permissions and restrict access to sensitive functionalities and data.
  - Requirement: Ensure that users can only access and modify data they are authorized to manage.
 - Input validation:
  - Requirement: Validate all user inputs to prevent injection attacks (e.g., SQL injection, command injection, XSS).
  - Requirement: Sanitize user inputs before storing them in the database or displaying them in the user interface.
  - Requirement: Implement proper error handling to avoid leaking sensitive information in error messages.
 - Cryptography:
  - Requirement: Use strong encryption algorithms and protocols for storing sensitive data at rest (e.g., database encryption).
  - Requirement: Use HTTPS to encrypt all communication between the client and the server to protect data in transit.
  - Requirement: Securely store and manage cryptographic keys.

# DESIGN

## C4 CONTEXT

```mermaid
flowchart LR
    subgraph "Personal User"
        U[User]
    end
    subgraph "Firefly III System"
        F(["Firefly III Application"])
    end
    subgraph "External Systems"
        B[Bank APIs]
        E[Email Service]
    end
    U --> F: Uses
    F --> B: Fetches data (Optional)
    F --> E: Sends notifications (Optional)
    style F fill:#f9f,stroke:#333,stroke-width:2px
```

- Elements of context diagram:
 - Element:
  - Name: Personal User
  - Type: Person
  - Description: Individual user who uses Firefly III to manage their personal finances.
  - Responsibilities: Manages personal finances, inputs financial data, views reports, configures the application.
  - Security controls: Strong passwords, enabling MFA (if implemented), keeping their devices secure.
 - Element:
  - Name: Firefly III Application
  - Type: Software System
  - Description: Self-hosted personal finance management application.
  - Responsibilities: Manages user accounts, stores financial data, provides budgeting and reporting features, interacts with external systems (optional).
  - Security controls: Authentication, authorization, input validation, data encryption, session management, security logging, regular updates.
 - Element:
  - Name: Bank APIs
  - Type: External System
  - Description: APIs provided by banks or financial institutions for automatic transaction import (optional).
  - Responsibilities: Provides transaction data to Firefly III (if configured by the user).
  - Security controls: API authentication (OAuth 2.0 or similar), secure API communication (HTTPS).
 - Element:
  - Name: Email Service
  - Type: External System
  - Description: Service used by Firefly III to send email notifications (optional), such as password reset emails or alerts.
  - Responsibilities: Sends emails on behalf of Firefly III.
  - Security controls: Secure SMTP connection (STARTTLS), SPF/DKIM/DMARC configuration.

## C4 CONTAINER

```mermaid
flowchart LR
    subgraph "Personal User"
        U[User Browser]
    end
    subgraph "Firefly III System"
        W[Web Server]
        A[Application Server]
        D[Database Server]
    end
    subgraph "External Systems"
        B[Bank APIs]
        E[Email Service]
    end
    U --> W: HTTPS requests
    W --> A: HTTP requests
    A --> D: Database queries
    A --> B: API calls (Optional)
    A --> E: SMTP (Optional)
    style W fill:#f9f,stroke:#333,stroke-width:2px
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style D fill:#f9f,stroke:#333,stroke-width:2px
```

- Elements of container diagram:
 - Element:
  - Name: User Browser
  - Type: Container
  - Description: User's web browser used to access the Firefly III application.
  - Responsibilities: Rendering user interface, interacting with the user, sending requests to the Web Server.
  - Security controls: Browser security features, user awareness of phishing and other web-based attacks.
 - Element:
  - Name: Web Server
  - Type: Container
  - Description: Web server (e.g., Nginx, Apache) that serves static content and proxies requests to the Application Server.
  - Responsibilities: Handling HTTPS connections, serving static files, reverse proxying requests, implementing security headers, rate limiting.
  - Security controls: HTTPS configuration, TLS certificates, security headers (CSP, HSTS, X-Frame-Options), rate limiting, web server access logs, firewall.
 - Element:
  - Name: Application Server
  - Type: Container
  - Description: PHP application server running the Firefly III application code.
  - Responsibilities: Handling application logic, user authentication and authorization, input validation, data processing, interacting with the Database Server and external systems.
  - Security controls: Application-level authentication and authorization, input validation, output encoding, CSRF protection, session management, secure coding practices, dependency vulnerability scanning, application logs.
 - Element:
  - Name: Database Server
  - Type: Container
  - Description: Database server (e.g., MySQL, PostgreSQL) storing application data.
  - Responsibilities: Storing and retrieving application data, ensuring data integrity and availability.
  - Security controls: Database access control, database user authentication, data encryption at rest (optional but recommended), database audit logs, regular backups, firewall.
 - Element:
  - Name: Bank APIs
  - Type: External System
  - Description: APIs provided by banks or financial institutions for automatic transaction import (optional).
  - Responsibilities: Provides transaction data to Firefly III (if configured by the user).
  - Security controls: API authentication (OAuth 2.0 or similar), secure API communication (HTTPS).
 - Element:
  - Name: Email Service
  - Type: External System
  - Description: Service used by Firefly III to send email notifications (optional), such as password reset emails or alerts.
  - Responsibilities: Sends emails on behalf of Firefly III.
  - Security controls: Secure SMTP connection (STARTTLS), SPF/DKIM/DMARC configuration.

## DEPLOYMENT

Deployment Solution: Docker Compose on a single server.

```mermaid
flowchart LR
    subgraph "Server"
        subgraph "Docker"
            W[Web Server Container]
            A[Application Server Container]
            D[Database Server Container]
        end
    end
    subgraph "Personal User"
        U[User Browser]
    end
    U --> W: HTTPS
    W --> A: HTTP
    A --> D: Database Protocol
    style W fill:#f9f,stroke:#333,stroke-width:2px
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style D fill:#f9f,stroke:#333,stroke-width:2px
```

- Elements of deployment diagram:
 - Element:
  - Name: Server
  - Type: Infrastructure Node
  - Description: Physical or virtual server running the Docker environment.
  - Responsibilities: Hosting the Docker containers, providing network connectivity, managing resources.
  - Security controls: Operating system security hardening, firewall, intrusion detection system, regular security patching, access control to the server.
 - Element:
  - Name: Docker
  - Type: Container Runtime Environment
  - Description: Docker runtime environment for containerizing and running the application components.
  - Responsibilities: Container orchestration, resource management, isolation of containers.
  - Security controls: Docker security best practices, container image scanning, resource limits for containers, Docker daemon security.
 - Element:
  - Name: Web Server Container
  - Type: Container Instance
  - Description: Docker container instance running the Web Server (e.g., Nginx).
  - Responsibilities: Serving static content, reverse proxying, handling HTTPS.
  - Security controls: Same as Web Server Container in C4 Container diagram.
 - Element:
  - Name: Application Server Container
  - Type: Container Instance
  - Description: Docker container instance running the Application Server (PHP).
  - Responsibilities: Application logic, authentication, authorization, data processing.
  - Security controls: Same as Application Server Container in C4 Container diagram.
 - Element:
  - Name: Database Server Container
  - Type: Container Instance
  - Description: Docker container instance running the Database Server (e.g., MySQL, PostgreSQL).
  - Responsibilities: Data storage and retrieval.
  - Security controls: Same as Database Server Container in C4 Container diagram.
 - Element:
  - Name: User Browser
  - Type: Client Device
  - Description: User's web browser.
  - Responsibilities: Accessing the application.
  - Security controls: Same as User Browser in C4 Container diagram.

## BUILD

```mermaid
flowchart LR
    subgraph "Developer Workstation"
        DEV[Developer]
        CODE[Source Code]
    end
    subgraph "CI/CD Pipeline (e.g., GitHub Actions)"
        VC[Version Control System (GitHub)]
        BUILD[Build Automation]
        TEST[Security Scanners (SAST, Dependency Check)]
        PUBLISH[Publish Artifacts (Docker Image Registry)]
    end
    DEV --> CODE: Writes Code
    CODE --> VC: Commits Code
    VC --> BUILD: Triggers Build
    BUILD --> TEST: Runs Security Tests
    TEST --> PUBLISH: On Success
    PUBLISH --> DEPLOY[Deployment Environment]: Deploy Image
    style BUILD fill:#f9f,stroke:#333,stroke-width:2px
    style TEST fill:#f9f,stroke:#333,stroke-width:2px
    style PUBLISH fill:#f9f,stroke:#333,stroke-width:2px
```

- Elements of build diagram:
 - Element:
  - Name: Developer
  - Type: Person
  - Description: Software developer contributing to the Firefly III project.
  - Responsibilities: Writing code, committing code, performing local testing.
  - Security controls: Secure coding practices, code reviews, workstation security.
 - Element:
  - Name: Source Code
  - Type: Code Repository
  - Description: Firefly III source code repository.
  - Responsibilities: Storing source code, tracking changes, version control.
  - Security controls: Access control to the repository, code review process, branch protection.
 - Element:
  - Name: Version Control System (GitHub)
  - Type: Tool
  - Description: GitHub platform used for version control and CI/CD.
  - Responsibilities: Hosting code repository, managing branches, triggering CI/CD pipelines.
  - Security controls: Access control, audit logs, security features of GitHub platform.
 - Element:
  - Name: Build Automation
  - Type: CI/CD Pipeline Stage
  - Description: Automated build process using CI/CD tools (e.g., GitHub Actions).
  - Responsibilities: Compiling code, building artifacts (e.g., Docker images), running tests.
  - Security controls: Secure build environment, minimal permissions for build processes, build process hardening.
 - Element:
  - Name: Security Scanners (SAST, Dependency Check)
  - Type: CI/CD Pipeline Stage
  - Description: Automated security scanning tools integrated into the CI/CD pipeline.
  - Responsibilities: Static Application Security Testing (SAST), dependency vulnerability scanning, identifying potential security issues.
  - Security controls: Regularly updated scanners, configured to detect relevant vulnerabilities, fail build on critical findings.
 - Element:
  - Name: Publish Artifacts (Docker Image Registry)
  - Type: Artifact Repository
  - Description: Docker image registry for storing and distributing built Docker images.
  - Responsibilities: Storing and managing Docker images, providing access to images for deployment.
  - Security controls: Access control to the registry, image signing, vulnerability scanning of published images.
 - Element:
  - Name: Deployment Environment
  - Type: Environment
  - Description: Target environment where Firefly III is deployed (e.g., user's server).
  - Responsibilities: Running the application, providing runtime environment.
  - Security controls: Security controls of the deployment environment (as described in DEPLOYMENT section).

# RISK ASSESSMENT

- Critical business process we are trying to protect:
 - Process: Securely managing and storing user's personal financial data.
 - Process: Ensuring availability and integrity of the application and user data.
 - Process: Maintaining user privacy and confidentiality of financial information.

- Data we are trying to protect and their sensitivity:
 - Data: User credentials (passwords). Sensitivity: Highly sensitive. Requires strong encryption and access control.
 - Data: Financial transactions, account balances, budget information. Sensitivity: Sensitive. Requires confidentiality, integrity, and availability.
 - Data: Personal information (name, email, etc.). Sensitivity: Sensitive. Requires protection under data privacy regulations.
 - Data: Application logs. Sensitivity: Moderate. May contain sensitive information and should be protected from unauthorized access.

# QUESTIONS & ASSUMPTIONS

- Questions:
 - Question: What is the intended scale of deployment (number of users, data volume)? (Assumption: Small to medium scale, personal use).
 - Question: Are there any specific compliance requirements (e.g., GDPR, PCI DSS)? (Assumption: Primarily personal use, compliance requirements are user's responsibility).
 - Question: What is the user's technical proficiency level? (Assumption: Varied, ranging from technically savvy to less experienced users).
 - Question: Are there plans for future integrations with other services beyond bank APIs and email? (Assumption: Focus is currently on core personal finance management features).

- Assumptions:
 - BUSINESS POSTURE: The primary business goal is to provide a useful and secure self-hosted personal finance management tool for individuals. Data privacy and security are paramount.
 - SECURITY POSTURE: Users are responsible for securing their own infrastructure. Firefly III aims to provide secure software, but user configuration and environment play a significant role in overall security. Security controls are focused on application-level security and guidance for users.
 - DESIGN: The application follows a standard three-tier web application architecture (Web Server, Application Server, Database Server). Deployment is primarily self-hosted, with Docker Compose being a common and recommended method.