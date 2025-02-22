- **Vulnerability Name:** Insecure PostgreSQL Authentication Configuration in Docker Compose

  - **Description:**
    The project’s Docker Compose configuration (file: `/code/docker-compose.yml`) sets up a PostgreSQL container with the environment variable `POSTGRES_HOST_AUTH_METHOD` explicitly set to `"trust"`. This means that the database is configured to accept any connection without requiring a password. An external attacker who can reach the exposed PostgreSQL port (mapped as `5432:5432`) would be able to connect freely—without providing credentials—and then issue arbitrary SQL commands.
    **Step-by-step exploitation process:**
    1. The attacker scans the public IP of the deployed instance and finds port 5432 open.
    2. Using any PostgreSQL client (for example, the command‑line tool “psql”), the attacker connects with a command such as:
       ```
       psql -h <target_ip> -U postgres modelutils
       ```
       Since no password is required (because of the “trust” setting), the connection succeeds.
    3. Once connected, the attacker can query, update, or delete data within the database.
    4. In a worst‑case scenario, the attacker might be able to drop tables or exfiltrate sensitive data if the database holds production data.

  - **Impact:**
    An attacker can gain full access to the PostgreSQL database without authentication. This unauthorized access could lead to complete data compromise—including reading sensitive information, altering records, or even deleting the database—resulting in data loss and service disruption.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    There are no additional safeguards immediately visible in the project files; the Docker Compose configuration simply appoints `POSTGRES_HOST_AUTH_METHOD` to `"trust"` and exposes port 5432 directly.

  - **Missing Mitigations:**
    - Switching to a secure authentication method (e.g. using a strong, randomized password for the PostgreSQL user via `POSTGRES_PASSWORD` rather than “trust”).
    - Restricting network access by removing or remapping the exposed port when not in a secure, private environment (or using firewall rules).
    - Using environment‐specific configurations so that development/test settings are not deployed in a production environment.

  - **Preconditions:**
    - The PostgreSQL container is deployed with the current Docker Compose file configuration.
    - The container’s port 5432 is accessible from the public network (or there is insufficient network segmentation/firewalling).

  - **Source Code Analysis:**
    - In `/code/docker-compose.yml`, under the `postgres` service, the environment is configured as follows:
      ```
      services:
        postgres:
          image: postgres:13-alpine
          environment:
            POSTGRES_HOST_AUTH_METHOD: trust
            POSTGRES_DB: modelutils
            POSTGRES_USER: postgres
          ports:
          - 5432:5432
      ```
      By setting `POSTGRES_HOST_AUTH_METHOD` to `trust`, PostgreSQL is instructed to allow any connection without verifying credentials. Combined with the port mapping that exposes the standard PostgreSQL port, this configuration creates a clear pathway for unauthenticated external access.

  - **Security Test Case:**
    1. **Preparation:**
       - Ensure that the PostgreSQL container is running using the provided Docker Compose file and that port 5432 is reachable from an external host (or simulate public exposure on your test network).
    2. **Execution:**
       - From a command‑line tool or any PostgreSQL client on a machine outside the container’s host security perimeter, attempt to connect without providing a password. For example:
         ```
         psql -h <target_ip> -U postgres modelutils
         ```
    3. **Expected Result:**
       - The connection should succeed without prompting for a password, and commands such as `\dt` (to list tables) or simple SELECT queries should work normally.
    4. **Verification:**
       - Demonstrate that sensitive data or database modification commands can be executed due to the lack of authentication.
       - Document that an unauthenticated external user is able to connect and execute SQL statements, confirming the vulnerability.