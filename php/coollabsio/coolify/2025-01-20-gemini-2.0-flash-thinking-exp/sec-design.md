# Project Design Document: Coolify - Improved

**Version:** 1.1
**Date:** October 26, 2023
**Author:** AI Software Architect

## 1. Introduction

This document provides an enhanced architectural design for the Coolify project, an open-source, self-hostable platform for deploying web applications and databases. Building upon the previous version, this document offers more detailed insights into the system's components, interactions, data flow, and key technologies. It remains the foundation for subsequent threat modeling activities.

### 1.1. Purpose

The purpose of this document is to:

* Clearly define the architecture of the Coolify project with greater detail.
* Identify the key components and their specific responsibilities and data handling.
* Describe the interactions and the *type* of data flowing between components.
* Outline the technologies used in the project and their relevance.
* Provide a more robust basis for identifying potential security threats and vulnerabilities.

### 1.2. Scope

This document covers the core architectural design of the Coolify platform as represented in the provided GitHub repository (https://github.com/coollabsio/coolify). It focuses on the major components involved in managing application and database deployments, with a deeper dive into their functionalities.

### 1.3. Goals

The goals of this design document are to:

* Provide a clear, concise, and more detailed overview of the Coolify architecture.
* Enable more effective and targeted threat modeling and security analysis.
* Facilitate a deeper understanding for new developers and stakeholders.
* Serve as a more comprehensive reference point for future development, maintenance, and security audits.

## 2. High-Level Architecture

The Coolify platform can be broadly categorized into the following high-level components:

* **User Interface (Web UI):** The front-end application providing a graphical interface for users to interact with Coolify.
* **Backend API:** The core application logic responsible for handling user requests, managing deployments, and interacting with infrastructure providers.
* **Database:** Stores the application's persistent data, including user information, application configurations, and deployment status.
* **Job Queue:** Manages asynchronous tasks, such as deployment processes and background operations.
* **Agent (Optional):** A component installed on remote servers to facilitate deployments and management on those servers.
* **External Providers:**  Third-party services and technologies used for deployments, such as Docker, remote servers (via SSH), etc.

```mermaid
graph LR
    subgraph "Coolify Platform"
        A["User"] -->| "HTTP Requests/Responses"| B("Web UI");
        B -->| "API Requests (JSON)"| C("Backend API");
        C -->| "Data Queries/Mutations"| D("Database");
        C -->| "Task Enqueue/Dequeue"| E("Job Queue");
        C -->| "Commands/Status Updates"| F("Agent (Optional)");
    end
    C -->| "API Calls/CLI Commands"| G["External Providers (Docker, SSH, etc.)"];
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style B fill:#ccf,stroke:#333,stroke-width:2px
    style C fill:#ccf,stroke:#333,stroke-width:2px
    style D fill:#ccf,stroke:#333,stroke-width:2px
    style E fill:#ccf,stroke:#333,stroke-width:2px
    style F fill:#ccf,stroke:#333,stroke-width:2px
    style G fill:#ccf,stroke:#333,stroke-width:2px
```

## 3. Component Details

This section provides a more detailed description of each component within the Coolify architecture, including the types of data they handle and their specific interactions.

### 3.1. User Interface (Web UI)

* **Purpose:** Provides a user-friendly interface for managing applications, databases, and server configurations within Coolify.
* **Responsibilities:**
    * Presenting application state, server details, and deployment logs to the user.
    * Accepting user input for actions like creating applications, deploying changes, and managing settings.
    * Communicating with the Backend API via RESTful API calls (likely JSON payloads) to perform operations.
    * Handling user authentication and authorization state based on tokens received from the Backend API.
* **Key Features:**
    * Application creation (name, repository details, build settings).
    * Database creation (type, version, credentials).
    * Server connection management (host, SSH keys, Docker socket details).
    * Deployment configuration (environment variables, resource limits).
    * Real-time monitoring of deployment status and application logs.
    * User and team management (roles, permissions).
* **Data Handled:**
    * User credentials (during login, transmitted securely).
    * Application configuration data (names, settings, environment variables).
    * Deployment specifications.
    * Server connection details.
    * Real-time logs and status updates.
* **Technology:** Likely built using a modern JavaScript framework (e.g., React, Vue.js, Svelte), potentially with state management libraries and UI component libraries.

### 3.2. Backend API

* **Purpose:**  The core logic of the Coolify platform, responsible for processing user requests, managing application deployments, and interacting with external providers.
* **Responsibilities:**
    * Authenticating and authorizing user requests based on session tokens or API keys.
    * Receiving and validating requests from the Web UI (likely JSON payloads).
    * Orchestrating the entire deployment lifecycle, including building, pushing images, and running containers.
    * Interacting with the Database to store and retrieve application configurations, deployment history, and user data.
    * Managing the Job Queue by enqueuing tasks for asynchronous operations.
    * Communicating with Agents on remote servers via secure channels (e.g., SSH tunnels or dedicated connections).
    * Interacting with External Providers (Docker API, SSH clients, etc.) using their respective APIs or command-line interfaces.
* **Key Features:**
    * RESTful API endpoints for all UI functionalities (e.g., `/api/applications`, `/api/deployments`).
    * Business logic for complex deployment workflows, including build processes and health checks.
    * Security enforcement (authentication, authorization, input validation, rate limiting).
    * Management of application and database configurations, including secure storage of secrets.
    * Monitoring and logging of system activities, errors, and security events.
* **Data Handled:**
    * User credentials (for authentication).
    * Application configurations (stored securely, potentially encrypted).
    * Deployment specifications and parameters.
    * Server connection credentials (stored securely, potentially encrypted).
    * API keys and tokens for external providers (stored securely, potentially encrypted).
    * Deployment logs and status updates.
* **Technology:** Likely built using a backend framework (e.g., Node.js with Express/NestJS, Python with Django/Flask, Go with Gin/Echo), potentially with ORM/ODM libraries for database interaction and task queue clients.

### 3.3. Database

* **Purpose:**  Stores persistent data for the Coolify platform, ensuring data integrity and availability.
* **Responsibilities:**
    * Storing user accounts and authentication details (hashed passwords, API keys).
    * Storing application configurations, including environment variables (potentially encrypted), build settings, and deployment configurations.
    * Storing database configurations and connection details (credentials encrypted).
    * Tracking deployment status, history, and logs.
    * Storing server connection information (credentials encrypted).
    * Managing relationships between users, teams, projects, applications, and servers.
* **Key Data Entities:**
    * `Users` (username, email, password hash, roles).
    * `Teams` (name, members, permissions).
    * `Projects` (name, associated applications and databases).
    * `Applications` (name, repository URL, build commands, environment variables).
    * `Databases` (type, version, connection strings, credentials).
    * `Servers` (hostname, IP address, connection details, agent status).
    * `Deployments` (status, start/end times, logs, associated application and server).
    * `Settings` (global configurations, provider credentials).
* **Technology:**  Likely a relational database (e.g., PostgreSQL, MySQL) for structured data and relationships, potentially with encryption at rest.

### 3.4. Job Queue

* **Purpose:**  Manages asynchronous tasks that do not need to be executed immediately in the request-response cycle, improving performance and resilience.
* **Responsibilities:**
    * Receiving tasks from the Backend API, typically containing instructions for deployment operations, database management, or server provisioning.
    * Queuing tasks for processing, ensuring tasks are executed in order or based on priority.
    * Executing tasks in the background, potentially using worker processes or threads.
    * Providing feedback on task status (success, failure, progress) to the Backend API.
    * Implementing retry mechanisms for failed tasks.
* **Key Tasks:**
    * Application deployments (building, pushing images, running containers).
    * Database creation, migration, and backup.
    * Server provisioning and configuration (installing dependencies, configuring services).
    * Sending notifications (email, Slack, etc.).
    * Running scheduled tasks.
* **Data Handled:**
    * Task payloads containing instructions and data for specific operations (e.g., deployment details, database credentials).
    * Task status updates.
* **Technology:**  Likely a message queue system (e.g., Redis with a queuing library, RabbitMQ, Kafka) or a dedicated task queue library (e.g., Celery for Python).

### 3.5. Agent (Optional)

* **Purpose:**  A lightweight component installed on remote servers that are managed by Coolify. It facilitates secure communication and execution of commands on those servers.
* **Responsibilities:**
    * Establishing a secure connection with the Backend API (e.g., using SSH tunnels or mutually authenticated TLS).
    * Receiving commands from the Backend API, such as Docker commands, shell scripts, or system management tasks.
    * Executing commands on the remote server with appropriate privileges.
    * Reporting the status of command execution (success, failure, output) back to the Backend API.
    * Potentially monitoring server resources (CPU, memory, disk usage) and reporting back to the Backend API.
* **Key Interactions:**
    * Receives deployment instructions (e.g., `docker compose up`, `docker pull`) from the Backend API.
    * Executes commands related to application lifecycle management (start, stop, restart).
    * Sends logs and status updates back to the Backend API over the secure connection.
* **Data Handled:**
    * Commands to be executed on the remote server.
    * Output and status of executed commands.
    * Potentially server resource utilization data.
* **Technology:**  Likely a lightweight application written in a language suitable for system-level operations and network communication (e.g., Go, Python, Rust), designed for minimal resource consumption.

### 3.6. External Providers

* **Purpose:**  External services and technologies that Coolify integrates with to perform deployments and manage infrastructure.
* **Examples:**
    * **Docker:** Used for building, pushing, and pulling container images and managing container lifecycles. The Backend API or Agent interacts with the Docker daemon via the Docker API or command-line interface.
    * **Remote Servers (via SSH):** Allows Coolify to manage applications on existing servers by executing commands over SSH. The Backend API uses SSH clients to connect and execute commands.
    * **Git Repositories (e.g., GitHub, GitLab, Bitbucket):** Used for fetching application source code. The Backend API interacts with Git repositories via HTTPS or SSH.
    * **Container Registries (e.g., Docker Hub, GitLab Container Registry):** Used for storing and retrieving container images. The Backend API interacts with container registries via their APIs.
    * **Cloud Providers (Future):** Potential integration with AWS, Azure, GCP for managed services like databases or container orchestration.
* **Interactions:**
    * The Backend API interacts with these providers using their respective APIs (RESTful, SDKs) or command-line interfaces, often requiring API keys or credentials.
    * The Agent (if used) may interact directly with Docker on remote servers, but the orchestration is managed by the Backend API.
* **Data Handled:**
    * API keys and tokens for authentication with external providers (handled securely by the Backend API).
    * Container images.
    * Source code.
    * Deployment manifests and configurations.

## 4. Data Flow

This section describes the typical flow of data for key operations within Coolify, highlighting the type of data exchanged.

### 4.1. User Login

```mermaid
graph LR
    A["User"] -->| "HTTPS Request (Credentials)"| B("Web UI");
    B -->| "HTTPS Request (Credentials - JSON)"| C("Backend API");
    C -->| "SQL Query (Username Lookup)"| D("Database");
    D -->| "User Data (Password Hash)"| C;
    C -->| "Authentication Result, Session Token (JWT)"| B;
    B -->| "Session Token (Authorization Header/Cookie)"| A;
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style B fill:#ccf,stroke:#333,stroke-width:2px
    style C fill:#ccf,stroke:#333,stroke-width:2px
    style D fill:#ccf,stroke:#333,stroke-width:2px
```

### 4.2. Application Deployment

```mermaid
graph LR
    A["User"] -->| "HTTPS Request (Deployment Request - JSON)"| B("Web UI");
    B -->| "HTTPS Request (Deployment Request - JSON)"| C("Backend API");
    C -->| "SQL Query (Fetch App Config, Server Details)"| D("Database");
    D -->| "Application Configuration, Server Details"| C;
    C -->| "Enqueue Task (Deployment Instructions - JSON)"| E("Job Queue");
    subgraph "Deployment Task Execution"
        direction LR
        E -->| "Task Payload (Deployment Instructions)"| F("Agent (Optional)");
        E -->| "Task Payload (Deployment Instructions)"| G["External Providers (Docker, SSH)"];
        F -->| "Commands (e.g., Docker commands)"| G;
        G -->| "Deployment Status/Logs"| E;
    end
    E -->| "Update Query (Deployment Status)"| C;
    C -->| "Websocket Update (Deployment Status)"| B;
    B -->| "Display Deployment Status"| A;
    style A fill:#f9f,stroke:#333,stroke-width:2px
    style B fill:#ccf,stroke:#333,stroke-width:2px
    style C fill:#ccf,stroke:#333,stroke-width:2px
    style D fill:#ccf,stroke:#333,stroke-width:2px
    style E fill:#ccf,stroke:#333,stroke-width:2px
    style F fill:#ccf,stroke:#333,stroke-width:2px
    style G fill:#ccf,stroke:#333,stroke-width:2px
```

## 5. Security Considerations (Initial)

Expanding on the previous considerations, here are more specific security aspects related to the Coolify architecture:

* **Authentication and Authorization:**
    * Securely storing user credentials using strong hashing algorithms.
    * Implementing robust authorization mechanisms (e.g., RBAC) to control access to resources and actions.
    * Protecting API endpoints with authentication (e.g., JWT, API keys).
* **Data Security:**
    * Encrypting sensitive data at rest in the database (e.g., using database encryption features).
    * Ensuring secure transmission of data between components using HTTPS/TLS.
    * Securely managing and storing secrets (API keys, database credentials) using dedicated secrets management solutions or encrypted configuration.
* **Input Validation:**
    * Thoroughly validating all user inputs on both the client-side and server-side to prevent injection attacks (SQL injection, command injection, XSS).
    * Sanitizing user-provided data before storing it in the database or using it in commands.
* **Secrets Management:**
    * Avoiding hardcoding secrets in the codebase.
    * Utilizing environment variables or dedicated secrets management tools (e.g., HashiCorp Vault, Kubernetes Secrets).
    * Encrypting secrets at rest and in transit.
* **Network Security:**
    * Enforcing HTTPS for all communication between the Web UI and the Backend API.
    * Securing communication between the Backend API and the Agent (e.g., using SSH tunnels, mutually authenticated TLS).
    * Implementing network segmentation to isolate components.
    * Properly configuring firewalls to restrict access to services.
* **Dependency Management:**
    * Regularly scanning dependencies for known vulnerabilities and updating them.
    * Using software composition analysis (SCA) tools.
* **Agent Security:**
    * Ensuring the Agent is securely authenticated and authorized to communicate with the Backend API.
    * Protecting the Agent from unauthorized access and tampering on the remote server.
    * Minimizing the Agent's attack surface.
* **External Provider Security:**
    * Securely storing and managing credentials for external providers.
    * Following security best practices for interacting with external APIs.
    * Limiting the permissions granted to Coolify for external providers.
* **Rate Limiting:**
    * Implementing rate limiting on authentication endpoints and other critical API endpoints to prevent brute-force attacks and denial-of-service.
* **Logging and Monitoring:**
    * Implementing comprehensive logging of security-related events (authentication attempts, authorization failures, API access).
    * Monitoring system logs for suspicious activity.
    * Setting up alerts for potential security incidents.

## 6. Technologies Used

This section details the likely technologies used and their relevance to the project:

* **Programming Languages:**
    * **JavaScript/TypeScript:** For the frontend Web UI, providing interactivity and a dynamic user experience. TypeScript adds static typing for improved code maintainability.
    * **Node.js:** A likely choice for the Backend API due to its scalability and large ecosystem, especially when combined with frameworks like Express or NestJS.
    * **Go or Python:** Potential choices for the Agent due to their efficiency and suitability for system-level operations and network programming.
* **Frontend Framework:**
    * **React, Vue.js, or Svelte:** Popular choices for building modern single-page applications, offering component-based architectures and efficient rendering.
* **Backend Framework:**
    * **Express.js or NestJS (Node.js):** Provide structure and features for building robust and scalable APIs.
    * **Django or Flask (Python):** Mature frameworks for building web applications and APIs.
    * **Gin or Echo (Go):** Lightweight and performant frameworks for building APIs in Go.
* **Database:**
    * **PostgreSQL:** A robust and feature-rich open-source relational database, often preferred for its reliability and data integrity features.
    * **MySQL:** Another popular open-source relational database.
* **Job Queue:**
    * **Redis:** Often used as a message broker and task queue due to its speed and versatility.
    * **RabbitMQ:** A more feature-rich message broker with advanced queuing capabilities.
* **Containerization:**
    * **Docker:** Essential for packaging and deploying applications in isolated containers, ensuring consistency across different environments.
* **Operating System:**
    * **Linux:** The most common operating system for server deployments due to its stability, security, and open-source nature.
* **Networking:**
    * **TCP/IP:** The fundamental networking protocol suite.
    * **HTTPS/TLS:** For secure communication over the internet.
    * **SSH:** For secure remote access and command execution.

## 7. Deployment Architecture

Coolify's self-hosted nature allows for various deployment architectures:

* **Single Server Deployment (All-in-One):** All components (Web UI, Backend API, Database, Job Queue) are deployed on a single server, often using Docker Compose for orchestration. This is suitable for development and small-scale deployments.
* **Multi-Server Deployment (Separated Services):** Components are deployed on separate servers for improved scalability, resilience, and security.
    * **Dedicated Database Server:** The database runs on its own server for better performance and security.
    * **Load-Balanced Backend API:** Multiple instances of the Backend API are deployed behind a load balancer to handle increased traffic.
    * **Separate Job Queue Server:** The message queue system runs on its own server.
    * **Web UI on a Separate Server or CDN:** The frontend can be served from a dedicated server or a Content Delivery Network (CDN).
* **Agent Deployment on Managed Servers:** The Agent component is installed on each remote server that Coolify manages, enabling secure communication and command execution.

## 8. Future Considerations

Building upon the initial future considerations, here are more specific potential enhancements:

* **Enhanced Cloud Provider Integrations:** Deeper integration with specific cloud provider services (e.g., AWS ECS/EKS, Azure Container Instances, Google Cloud Run) for more streamlined deployments.
* **Advanced Monitoring and Alerting:** Integration with monitoring tools (e.g., Prometheus, Grafana) and alerting systems for proactive issue detection.
* **Granular Role-Based Access Control (RBAC):** More fine-grained control over user permissions and access to specific resources and actions within Coolify.
* **Support for More Deployment Strategies:** Implementing support for advanced deployment strategies like blue/green deployments, canary releases, and rolling updates.
* **Automated Vulnerability Scanning:** Integrating with vulnerability scanning tools to automatically identify and report security vulnerabilities in dependencies and container images.
* **Backup and Restore Functionality:** Implementing robust backup and restore mechanisms for the database and application configurations.
* **Improved Logging and Auditing:** More detailed logging of user actions and system events for auditing and security analysis.

This improved design document provides a more comprehensive understanding of the Coolify project's architecture, offering a stronger foundation for effective threat modeling and future development efforts. The detailed component descriptions, data flow diagrams, and security considerations provide valuable insights for identifying potential vulnerabilities and designing appropriate security controls.