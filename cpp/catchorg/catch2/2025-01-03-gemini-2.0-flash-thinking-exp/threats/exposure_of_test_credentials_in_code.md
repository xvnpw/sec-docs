```cpp
#include "catch2/catch_test_macros.hpp"
#include <string>
#include <cstdlib> // For std::getenv

// Example showing how *NOT* to hardcode credentials
// This is for demonstration purposes only - DO NOT DO THIS IN REAL CODE!
// const std::string hardcoded_username = "testuser";
// const std::string hardcoded_password = "P@$$wOrd!";

TEST_CASE("External Service Authentication") {
    // Retrieve credentials from environment variables
    const char* username_env = std::getenv("TEST_USERNAME");
    const char* password_env = std::getenv("TEST_PASSWORD");

    REQUIRE(username_env != nullptr);
    REQUIRE(password_env != nullptr);

    std::string username = username_env;
    std::string password = password_env;

    // Simulate authentication logic (replace with actual service interaction)
    bool authenticated = false;
    if (username == "valid_test_user" && password == "secure_test_password") {
        authenticated = true;
    }

    REQUIRE(authenticated);
}

TEST_CASE("Database Connection Test") {
    // Retrieve database connection string from environment variable
    const char* connection_string_env = std::getenv("TEST_DB_CONNECTION_STRING");
    REQUIRE(connection_string_env != nullptr);
    std::string connection_string = connection_string_env;

    // Simulate database connection logic (replace with actual database interaction)
    bool connection_successful = false;
    if (connection_string.find("valid_db_credentials") != std::string::npos) {
        connection_successful = true;
    }

    REQUIRE(connection_successful);
}

// Example demonstrating the use of a configuration file (not directly in the test)
// Assume you have a test_config.ini or similar file
// This shows the principle of externalizing configuration
#include <fstream>
#include <sstream>

struct TestConfig {
    std::string api_key;
};

TestConfig load_test_config(const std::string& filename) {
    TestConfig config;
    std::ifstream file(filename);
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value)) {
            if (key == "API_KEY") {
                config.api_key = value;
            }
            // Add more configuration parameters as needed
        }
    }
    return config;
}

TEST_CASE("API Interaction with Config File") {
    TestConfig config = load_test_config("test_config.ini");
    REQUIRE(!config.api_key.empty());

    // Use config.api_key for API calls
    // ...
}
```