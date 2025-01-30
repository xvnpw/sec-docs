# BUSINESS POSTURE

This project, reveal.js, is an open-source HTML presentation framework. Its primary business priority is to provide a flexible and feature-rich tool for creating web-based presentations. The goal is to empower users to create visually appealing and interactive presentations using web technologies, making presentations accessible and distributable via the web.

Key business goals include:
- Providing a user-friendly and customizable presentation framework.
- Maintaining a high-quality, stable, and well-documented codebase.
- Fostering a community of users and contributors.
- Ensuring compatibility with modern web browsers and technologies.

Most important business risks that need to be addressed:
- Availability risk: If the project website or CDN hosting the library becomes unavailable, users may not be able to access or use reveal.js.
- Data confidentiality risk: Presentations created with reveal.js might contain sensitive information. If not properly secured by the user hosting the presentation, this data could be exposed.
- Reputational risk: Security vulnerabilities in reveal.js itself could damage the project's reputation and user trust.
- Supply chain risk: Compromise of dependencies used in the build process could introduce vulnerabilities into reveal.js.

# SECURITY POSTURE

Existing security controls:
- security control: HTTPS is used for the project website and likely for CDN distribution, ensuring transport security. (Observed on revealjs.com and likely standard practice for CDN providers).
- security control: Project is hosted on GitHub, leveraging GitHub's security features for code repository management and access control. (GitHub platform security).
- security control: Open-source nature of the project allows for community review and scrutiny of the code, potentially identifying and addressing security issues. (Open source community review).
- accepted risk: Security of user-created presentations and their hosting environment is the responsibility of the user. Reveal.js provides the framework, but users are responsible for securing their content and where they deploy it.
- accepted risk: Reliance on client-side security. Reveal.js is a client-side library, and as such, it inherently trusts the client's browser environment.

Recommended security controls:
- security control: Implement automated dependency scanning in the build process to identify and address vulnerabilities in third-party libraries.
- security control: Provide clear documentation and best practices for users on how to securely host and serve reveal.js presentations, including recommendations for Content Security Policy (CSP) and other security headers.
- security control: Conduct regular security audits or penetration testing of the reveal.js codebase to proactively identify and address potential vulnerabilities.

Security requirements:
- Authentication: Not directly applicable to reveal.js library itself. Authentication is the responsibility of the system hosting the presentations if access control is required.
- Authorization: Not directly applicable to reveal.js library itself. Authorization is the responsibility of the system hosting the presentations to control access to specific presentations.
- Input validation: Reveal.js should ensure that it handles any user-provided input (e.g., configuration options, slide content if dynamically generated) safely to prevent injection vulnerabilities. However, core reveal.js functionality has limited direct user input. Plugins might introduce input handling requirements.
- Cryptography: Not a core requirement for reveal.js itself. Encryption of presentation content would be the responsibility of the user and handled outside of reveal.js, potentially at the hosting or delivery layer. If plugins are developed that handle sensitive data, cryptographic requirements might become relevant for those specific plugins.

# DESIGN

## C4 CONTEXT

```mermaid
flowchart LR
    subgraph "Presentation Viewers"
        PV[Presentation Viewers]
    end
    subgraph "Presentation Creators"
        PC[Presentation Creators]
    end
    REVEAL[Reveal.js]
    WEB[Web Browser]
    SERVER[Web Server]
    CDN[Content Delivery Network]
    PACKAGE[Package Manager (npm/yarn)]

    PC --> REVEAL
    PV --> WEB
    WEB --> SERVER
    WEB --> CDN
    SERVER --> REVEAL
    CDN --> REVEAL
    REVEAL --> PACKAGE

    linkStyle 0,1,2,3,4,5,6 stroke-width:2px;
```

Elements of context diagram:

- Name: Presentation Viewers
  - Type: Person
  - Description: Individuals who view presentations created with reveal.js.
  - Responsibilities: Viewing presentations in a web browser.
  - Security controls: Browser security controls, user device security.

- Name: Presentation Creators
  - Type: Person
  - Description: Individuals who create presentations using reveal.js.
  - Responsibilities: Developing presentation content, configuring reveal.js, deploying presentations.
  - Security controls: Secure development practices, protecting presentation content, secure deployment practices.

- Name: Reveal.js
  - Type: Software System
  - Description: The reveal.js JavaScript library and associated assets for creating web-based presentations.
  - Responsibilities: Rendering presentations in web browsers, providing presentation framework functionality, handling user configuration.
  - Security controls: Input validation (configuration), dependency management, secure coding practices.

- Name: Web Browser
  - Type: Software System
  - Description: Software application used by Presentation Viewers to access and view reveal.js presentations.
  - Responsibilities: Rendering HTML, CSS, and JavaScript, executing reveal.js code, displaying presentation content.
  - Security controls: Browser security features (CSP, XSS protection, etc.), sandboxing, plugin security.

- Name: Web Server
  - Type: Software System
  - Description: Server that hosts and serves reveal.js presentations and related assets.
  - Responsibilities: Serving static files (HTML, CSS, JavaScript, images), handling HTTP requests, potentially providing access control.
  - Security controls: Server hardening, access control mechanisms, HTTPS configuration, security monitoring.

- Name: Content Delivery Network (CDN)
  - Type: Software System
  - Description: Network of servers that can host and deliver reveal.js library and assets to improve performance and availability.
  - Responsibilities: Caching and delivering static files, reducing latency, increasing availability.
  - Security controls: CDN provider security controls, HTTPS delivery, access control to CDN configuration.

- Name: Package Manager (npm/yarn)
  - Type: Software System
  - Description: Package manager used by developers to install and manage reveal.js and its dependencies during development and build process.
  - Responsibilities: Dependency resolution, package installation, build script execution.
  - Security controls: Package registry security, dependency vulnerability scanning, integrity checks.

## C4 CONTAINER

```mermaid
flowchart LR
    subgraph "Presentation Viewers"
        PV[Presentation Viewers]
    end
    subgraph "Presentation Creators"
        PC[Presentation Creators]
    end
    subgraph "Web Browser Container"
        REVEALJS[Reveal.js Library]
        PRESENTATION[Presentation Content (HTML, Markdown, Images)]
    end
    subgraph "Web Server Container"
        WEBSERVERAPP[Web Server Application (e.g., Nginx, Apache)]
        STATICFILES[Static File Storage]
    end
    CDNCONTAINER[Content Delivery Network (CDN)]
    PACKAGEMANAGER[Package Manager (npm/yarn)]

    PC --> REVEALJS
    PV --> WEBBROWSERAPP
    WEBBROWSERAPP --> REVEALJS
    WEBBROWSERAPP --> PRESENTATION
    WEBSERVERAPP --> STATICFILES
    CDNCONTAINER --> REVEALJS
    CDNCONTAINER --> PRESENTATION
    REVEALJS --> PACKAGEMANAGER

    linkStyle 0,1,2,3,4,5,6 stroke-width:2px;
```

Elements of container diagram:

- Name: Reveal.js Library
  - Type: Container - JavaScript Library
  - Description: The core JavaScript library of reveal.js, responsible for presentation logic and rendering within the web browser.
  - Responsibilities: Handling slide transitions, managing presentation state, rendering UI elements, processing configuration options.
  - Security controls: Input validation (configuration), secure coding practices, dependency management.

- Name: Presentation Content (HTML, Markdown, Images)
  - Type: Container - Static Files
  - Description: The HTML, Markdown, image, and other asset files that constitute the actual presentation content created by users.
  - Responsibilities: Defining presentation structure, content, and visual appearance.
  - Security controls: Content Security Policy (CSP) to mitigate XSS, secure storage of content, input sanitization if content is dynamically generated.

- Name: Web Server Application (e.g., Nginx, Apache)
  - Type: Container - Web Server
  - Description: The web server software responsible for serving the reveal.js library and presentation content to web browsers.
  - Responsibilities: Handling HTTP requests, serving static files, potentially managing access control, logging.
  - Security controls: Server hardening, access control configuration, HTTPS configuration, security monitoring, web application firewall (WAF) if applicable.

- Name: Static File Storage
  - Type: Container - File System/Object Storage
  - Description: Storage system where reveal.js library files and presentation content are stored and accessed by the web server.
  - Responsibilities: Persistently storing static files, providing access to the web server.
  - Security controls: Access control lists (ACLs), encryption at rest, regular backups, vulnerability scanning of storage infrastructure.

- Name: Content Delivery Network (CDN)
  - Type: Container - CDN
  - Description:  A CDN used to distribute reveal.js library and presentation assets globally for faster and more reliable delivery.
  - Responsibilities: Caching and serving static files from geographically distributed servers, improving performance and availability.
  - Security controls: CDN provider security controls, HTTPS delivery, access control to CDN configuration, origin protection.

- Name: Package Manager (npm/yarn)
  - Type: Container - Package Management Tool
  - Description: Tool used during development to manage dependencies of reveal.js project.
  - Responsibilities: Downloading and installing dependencies, running build scripts, managing project dependencies.
  - Security controls: Using trusted package registries, dependency vulnerability scanning, verifying package integrity (checksums, signatures).

## DEPLOYMENT

Deployment Solution: Static Hosting on Web Server/CDN

```mermaid
flowchart LR
    subgraph "User Device"
        WEB[Web Browser]
    end
    INTERNET[Internet]
    subgraph "Hosting Environment"
        LOADBALANCER[Load Balancer]
        WEBSERVER[Web Server Instance]
        STATICSTORAGE[Static File Storage (e.g., S3, Cloud Storage)]
        CDN[Content Delivery Network]
    end

    WEB -- HTTPS Request --> LOADBALANCER
    LOADBALANCER --> WEBSERVER
    WEBSERVER -- Retrieve Files --> STATICSTORAGE
    WEBSERVER -- Serve Files --> LOADBALANCER
    LOADBALANCER -- HTTPS Response --> WEB
    CDN -- Serve Files --> WEB
    STATICSTORAGE -- Replicate Files --> CDN

    linkStyle 0,1,2,3,4,5,6 stroke-width:2px;
```

Elements of deployment diagram:

- Name: User Device
  - Type: Infrastructure - End-user device
  - Description: The device used by Presentation Viewers to access presentations, typically a laptop, desktop, or mobile device.
  - Responsibilities: Running a web browser, connecting to the internet.
  - Security controls: Device security controls (antivirus, firewall, OS updates), user awareness of phishing and malware.

- Name: Internet
  - Type: Infrastructure - Network
  - Description: The public internet network connecting user devices to the hosting environment.
  - Responsibilities: Providing network connectivity.
  - Security controls: Network security controls are outside the scope of reveal.js project, relies on general internet security.

- Name: Load Balancer
  - Type: Infrastructure - Load Balancer
  - Description: Distributes incoming web traffic across multiple web server instances for scalability and availability.
  - Responsibilities: Traffic distribution, health checks, SSL termination.
  - Security controls: DDoS protection, access control, security monitoring, SSL/TLS configuration.

- Name: Web Server Instance
  - Type: Infrastructure - Virtual Machine/Container
  - Description: Individual web server instances running the web server application (e.g., Nginx, Apache) to serve reveal.js presentations.
  - Responsibilities: Serving static files, handling HTTP requests, potentially access control.
  - Security controls: Server hardening, OS security patching, intrusion detection, security logging, access control, firewall.

- Name: Static File Storage (e.g., S3, Cloud Storage)
  - Type: Infrastructure - Cloud Storage Service
  - Description: Cloud-based object storage service used to store reveal.js library files and presentation content.
  - Responsibilities: Persistent storage, scalability, availability, data redundancy.
  - Security controls: Access control policies (IAM), encryption at rest, versioning, audit logging, data replication.

- Name: Content Delivery Network (CDN)
  - Type: Infrastructure - CDN Service
  - Description: CDN service used to cache and deliver reveal.js assets globally.
  - Responsibilities: Caching static files, global content delivery, performance optimization.
  - Security controls: CDN provider security controls, origin protection, access control to CDN configuration, HTTPS delivery.

## BUILD

```mermaid
flowchart LR
    subgraph "Developer Workstation"
        DEV[Developer]
        CODE[Source Code (GitHub Repository)]
    end
    subgraph "CI/CD Pipeline (e.g., GitHub Actions)"
        BUILDSERVER[Build Server]
        DEPENDENCYSCAN[Dependency Scanner]
        SAST[SAST Scanner]
        LINTER[Linter]
        TESTS[Automated Tests]
        ARTIFACTS[Build Artifacts (Distribution Files)]
    end
    PUBLISH[Publish (npm, CDN, GitHub Releases)]

    DEV --> CODE
    CODE --> BUILDSERVER
    BUILDSERVER --> DEPENDENCYSCAN
    BUILDSERVER --> SAST
    BUILDSERVER --> LINTER
    BUILDSERVER --> TESTS
    DEPENDENCYSCAN --> BUILDSERVER
    SAST --> BUILDSERVER
    LINTER --> BUILDSERVER
    TESTS --> BUILDSERVER
    BUILDSERVER --> ARTIFACTS
    ARTIFACTS --> PUBLISH

    linkStyle 0,1,2,3,4,5,6,7,8,9,10,11,12,13 stroke-width:2px;
```

Elements of build diagram:

- Name: Developer
  - Type: Person
  - Description: Software developer contributing to the reveal.js project.
  - Responsibilities: Writing code, committing changes to the repository, running local builds and tests.
  - Security controls: Secure coding practices, code review, workstation security.

- Name: Source Code (GitHub Repository)
  - Type: Code Repository
  - Description: GitHub repository hosting the reveal.js source code.
  - Responsibilities: Version control, code storage, collaboration.
  - Security controls: Access control (GitHub permissions), branch protection, commit signing, vulnerability scanning (GitHub Dependabot).

- Name: Build Server
  - Type: Infrastructure - CI/CD Server
  - Description: Server in the CI/CD pipeline responsible for automating the build process.
  - Responsibilities: Building the project, running security scans, executing tests, creating build artifacts.
  - Security controls: Secure build environment, access control, secrets management, build isolation.

- Name: Dependency Scanner
  - Type: Tool - Security Scanner
  - Description: Tool used to scan project dependencies for known vulnerabilities.
  - Responsibilities: Identifying vulnerable dependencies, reporting vulnerabilities.
  - Security controls: Regularly updated vulnerability database, integration into build pipeline, fail-on-high-severity vulnerabilities.

- Name: SAST Scanner
  - Type: Tool - Security Scanner
  - Description: Static Application Security Testing (SAST) tool used to analyze source code for potential security vulnerabilities.
  - Responsibilities: Identifying potential code-level vulnerabilities (e.g., injection flaws, insecure configurations), reporting vulnerabilities.
  - Security controls: Regularly updated rule sets, integration into build pipeline, configurable severity thresholds.

- Name: Linter
  - Type: Tool - Code Quality Tool
  - Description: Tool used to analyze source code for code style issues and potential bugs.
  - Responsibilities: Enforcing code style guidelines, identifying potential code quality issues, improving code maintainability.
  - Security controls: Can help identify potential security-related code quality issues, configurable rules.

- Name: Automated Tests
  - Type: Tool - Testing Framework
  - Description: Automated tests (unit, integration, etc.) used to verify the functionality and stability of reveal.js.
  - Responsibilities: Ensuring code quality, detecting regressions, verifying functionality.
  - Security controls: Security-focused test cases (e.g., testing input validation, error handling), regular test execution.

- Name: Build Artifacts (Distribution Files)
  - Type: Files - Distribution Packages
  - Description: Compiled and packaged files ready for distribution (e.g., JavaScript files, CSS, assets, npm package).
  - Responsibilities: Packaging the project for distribution, creating distributable artifacts.
  - Security controls: Integrity checks (checksums, signatures), secure storage of artifacts, access control to artifacts.

- Name: Publish (npm, CDN, GitHub Releases)
  - Type: Distribution Platform
  - Description: Platforms used to publish and distribute reveal.js to users (npm registry, CDN, GitHub Releases).
  - Responsibilities: Making reveal.js available to users, distributing updates and new versions.
  - Security controls: Secure publishing process, access control to publishing platforms, integrity checks for published artifacts, HTTPS delivery.

# RISK ASSESSMENT

Critical business process we are trying to protect:
- Creation and delivery of web-based presentations using reveal.js.
- Availability and integrity of the reveal.js library itself for users.

Data we are trying to protect and their sensitivity:
- Presentation content: Sensitivity depends entirely on the content of individual presentations. Presentations can range from publicly available information to highly confidential business data, trade secrets, or personal information. The sensitivity is determined by the user creating the presentation, not by reveal.js itself.
- Reveal.js library code: While open source, maintaining the integrity and availability of the library code is important for the project's reputation and user trust. Code integrity prevents supply chain attacks and ensures users are using a safe and reliable library.

# QUESTIONS & ASSUMPTIONS

Questions:
- What is the intended audience and use cases for presentations created with reveal.js? (e.g., internal company presentations, public conferences, educational materials). This would help better understand the potential sensitivity of presentation content.
- Are there any specific compliance requirements that presentations created with reveal.js need to adhere to (e.g., GDPR, HIPAA)? This could influence security requirements for users hosting presentations.
- What is the process for handling security vulnerabilities reported in reveal.js? (e.g., security contact, vulnerability disclosure policy, patch release process).

Assumptions:
- BUSINESS POSTURE: The primary business goal is to provide a widely used and trusted open-source presentation framework. Success is measured by user adoption, community contributions, and project reputation.
- SECURITY POSTURE: Security responsibility is shared between the reveal.js project and its users. The project is responsible for the security of the library code and build/distribution process. Users are responsible for the security of their presentation content and hosting environment.
- DESIGN: Reveal.js is designed as a client-side JavaScript library intended for static hosting. Deployment typically involves serving static files from web servers or CDNs. The build process is automated using CI/CD pipelines and includes security checks like dependency scanning and SAST.