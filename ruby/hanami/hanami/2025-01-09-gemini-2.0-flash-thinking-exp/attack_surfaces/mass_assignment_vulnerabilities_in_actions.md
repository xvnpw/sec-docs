## Deep Analysis: Mass Assignment Vulnerabilities in Hanami Actions

This document provides a deep analysis of the "Mass Assignment Vulnerabilities in Actions" attack surface within applications built using the Hanami web framework. We will explore the mechanics of this vulnerability, its specific relevance to Hanami, provide detailed examples, assess the potential impact, and outline comprehensive mitigation strategies.

**1. Understanding Mass Assignment Vulnerabilities**

At its core, a mass assignment vulnerability occurs when an application directly uses data provided by a user (typically through HTTP request parameters) to update internal data structures, such as database records or object attributes, without proper validation or filtering. This allows attackers to potentially manipulate fields they shouldn't have access to, leading to unintended and potentially harmful consequences.

Imagine a form where a user updates their profile. Ideally, only fields like "name" and "email" should be updated. However, if the application blindly accepts all submitted parameters and uses them to update the user object, an attacker could inject malicious parameters like `is_admin: true` or `account_balance: 999999`.

**2. Hanami's Role in the Attack Surface**

Hanami, by design, emphasizes a clean separation of concerns and a direct interaction between actions and repositories. Actions receive HTTP request parameters, and repositories are responsible for interacting with the data store. This directness, while promoting clarity and efficiency, can become a vulnerability if not handled carefully.

Here's how Hanami contributes to this attack surface:

* **Direct Parameter Access:** Hanami actions provide direct access to request parameters through the `params` object. This makes it easy for developers to access and use this data.
* **Repository Update Methods:** Hanami repositories often have methods like `update` that accept an ID and a hash of attributes to update. If the hash of attributes is directly sourced from `params`, the vulnerability arises.
* **Lack of Built-in Strong Parameters:** Unlike frameworks like Ruby on Rails, Hanami doesn't have a built-in "strong parameters" feature that automatically filters and whitelists allowed attributes. This places the responsibility squarely on the developer to implement these safeguards.
* **Convention over Configuration:** While Hanami promotes convention, the specific implementation of data handling within actions and repositories is left to the developer. This flexibility, while powerful, can lead to inconsistencies and oversights regarding security best practices.

**3. Detailed Example and Exploitation Scenarios**

Let's expand on the provided example with a more detailed scenario:

**Vulnerable Action:**

```ruby
# app/actions/users/update.rb
module Web::Actions::Users
  class Update < Web::Action
    def handle(request, response)
      user = UserRepository.new.find(request.params[:id])
      if user
        UserRepository.new.update(user.id, request.params[:user]) # POTENTIAL VULNERABILITY
        response.status = 200
        response.body = "User updated successfully"
      else
        response.status = 404
        response.body = "User not found"
      end
    end
  end
end
```

**Vulnerable Repository:**

```ruby
# lib/my_app/repositories/user_repository.rb
class UserRepository < Hanami::Repository
end
```

**Exploitation Scenario:**

An attacker could send a malicious PATCH request to `/users/1` with the following request body (assuming JSON format):

```json
{
  "user": {
    "name": "Legitimate User",
    "email": "user@example.com",
    "is_admin": true,
    "account_balance": 999999
  }
}
```

In this scenario, if the `User` entity has attributes like `is_admin` and `account_balance`, the vulnerable code would directly update these fields based on the attacker's input.

**Consequences:**

* **Privilege Escalation:** The attacker could elevate their privileges by setting `is_admin: true`, gaining access to administrative functionalities.
* **Data Modification:** They could modify sensitive data like `account_balance`, leading to financial discrepancies or other data integrity issues.
* **Unauthorized Access:** Depending on the application logic, manipulating other fields could grant unauthorized access to resources or functionalities.

**4. Impact Assessment (Expanded)**

The impact of mass assignment vulnerabilities can be significant, ranging from minor annoyances to critical security breaches. Here's a more detailed breakdown:

* **Privilege Escalation (High Severity):** As demonstrated in the example, attackers can gain unauthorized administrative access, potentially taking control of the entire application and its data.
* **Data Modification/Corruption (High Severity):** Attackers can alter critical data, leading to incorrect information, business logic errors, and financial losses. This can damage trust and reputation.
* **Data Breaches (High Severity):** In some cases, mass assignment could be used to access or modify sensitive personal information, leading to privacy violations and legal repercussions.
* **Business Logic Manipulation (Medium to High Severity):** Attackers might be able to manipulate business rules by modifying relevant data fields, leading to unintended outcomes and financial gains for the attacker.
* **Denial of Service (Low to Medium Severity):** While less common, in some scenarios, manipulating certain fields could lead to application crashes or performance degradation, resulting in a denial of service.

**5. Comprehensive Mitigation Strategies (Detailed Implementation)**

Addressing mass assignment vulnerabilities requires a multi-layered approach. Here's a detailed look at the recommended mitigation strategies within the Hanami context:

* **Strong Parameters (Parameter Filtering):**

    * **Implementation:** Since Hanami doesn't provide this out-of-the-box, you need to implement it manually. This typically involves creating a helper method or a dedicated class to filter the incoming parameters.

    ```ruby
    # app/actions/users/update.rb
    module Web::Actions::Users
      class Update < Web::Action
        params do
          attribute :user, Types::Hash do
            attribute :name, Types::String
            attribute :email, Types::String
            # Explicitly allow only these attributes
          end
        end

        def handle(request, response)
          if request.params.valid?
            user = UserRepository.new.find(request.params[:id])
            if user
              UserRepository.new.update(user.id, request.params[:user].to_h)
              response.status = 200
              response.body = "User updated successfully"
            else
              response.status = 404
              response.body = "User not found"
            end
          else
            response.status = 400
            response.body = "Invalid parameters"
          end
        end
      end
    end
    ```

    * **Explanation:**  By defining the allowed attributes within the `params` block, you explicitly control which parameters are processed. Any other parameters in `request.params[:user]` will be ignored.

* **Attribute Whitelisting:**

    * **Implementation:** Explicitly select the allowed attributes before updating the model.

    ```ruby
    # app/actions/users/update.rb
    module Web::Actions::Users
      class Update < Web::Action
        def handle(request, response)
          user = UserRepository.new.find(request.params[:id])
          if user
            allowed_attributes = {
              name: request.params[:user][:name],
              email: request.params[:user][:email]
            }.compact # Remove nil values

            UserRepository.new.update(user.id, allowed_attributes)
            response.status = 200
            response.body = "User updated successfully"
          else
            response.status = 404
            response.body = "User not found"
          end
        end
      end
    end
    ```

    * **Explanation:**  This approach explicitly picks out the permitted attributes from the `params` hash and creates a new hash with only those values.

* **Use Case Specific Updates:**

    * **Implementation:** Instead of directly using `params`, extract and validate individual parameters relevant to the specific update operation. This often involves creating dedicated methods in your repositories or services.

    ```ruby
    # app/actions/users/update_profile.rb
    module Web::Actions::Users
      class UpdateProfile < Web::Action
        def handle(request, response)
          user = UserRepository.new.find(request.params[:id])
          if user
            name = request.params[:name]
            email = request.params[:email]

            # Perform validation on name and email if needed

            UserRepository.new.update_profile(user.id, name: name, email: email)
            response.status = 200
            response.body = "Profile updated successfully"
          else
            response.status = 404
            response.body = "User not found"
          end
        end
      end
    end

    # lib/my_app/repositories/user_repository.rb
    class UserRepository < Hanami::Repository
      def update_profile(id, attributes)
        update(id, attributes)
      end
    end
    ```

    * **Explanation:** This approach focuses on the specific intent of the action (e.g., updating the profile) and only accepts the parameters relevant to that intent.

* **Input Validation:**

    * **Implementation:** Validate the data types, formats, and constraints of the incoming parameters before using them to update the model. Hanami provides mechanisms for parameter validation within actions.

    ```ruby
    # app/actions/users/update.rb
    module Web::Actions::Users
      class Update < Web::Action
        params do
          attribute :user, Types::Hash do
            attribute :name, Types::String, min_length: 3
            attribute :email, Types::String, format: /@/
          end
        end

        # ... rest of the action
      end
    end
    ```

    * **Explanation:** While not directly preventing mass assignment, validation helps ensure that the data being used is in the expected format and prevents unexpected data from being processed.

* **Authorization Checks:**

    * **Implementation:** Always verify that the current user has the necessary permissions to update the specific resource and attributes they are attempting to modify. This prevents unauthorized users from exploiting mass assignment vulnerabilities.

    ```ruby
    # app/actions/users/update.rb
    module Web::Actions::Users
      class Update < Web::Action
        before :authenticate_user!
        before :authorize_update_user!

        # ... rest of the action

        private

        def authorize_update_user!
          unless current_user.admin? || current_user.id == request.params[:id].to_i
            halt 403, "Unauthorized"
          end
        end
      end
    end
    ```

    * **Explanation:** Even if an attacker manages to inject malicious parameters, authorization checks will prevent the update from succeeding if they lack the necessary permissions.

* **Code Reviews:**

    * **Importance:** Regular code reviews by security-conscious developers can help identify potential mass assignment vulnerabilities and ensure that proper mitigation strategies are in place.

* **Static Analysis Tools:**

    * **Implementation:** Utilize static analysis tools that can identify potential security vulnerabilities, including mass assignment. While they might not be perfect, they can provide valuable insights.

**6. Detection and Prevention During Development**

Proactive measures during development are crucial to prevent mass assignment vulnerabilities:

* **Security Awareness Training:** Educate developers about the risks of mass assignment and best practices for secure data handling.
* **Secure Coding Practices:** Emphasize the importance of explicitly defining allowed attributes and avoiding direct use of `params` for model updates.
* **Testing (See Section 7):** Implement thorough testing strategies to identify potential vulnerabilities.
* **Principle of Least Privilege:** Design actions and data models with the principle of least privilege in mind. Only allow necessary updates and avoid exposing sensitive attributes unnecessarily.

**7. Testing Strategies for Mass Assignment Vulnerabilities**

Effective testing is essential to identify and address mass assignment vulnerabilities. Here are some key strategies:

* **Manual Testing with Crafted Requests:**
    * **Technique:** Send requests with unexpected parameters, including those that should not be updatable (e.g., `is_admin`, `created_at`).
    * **Focus:** Verify that these extra parameters are ignored and do not modify the model.
    * **Tools:** Use tools like `curl`, Postman, or browser developer tools to craft and send these requests.

* **Automated Integration Tests:**
    * **Technique:** Write integration tests that specifically target actions that perform updates. Include test cases that attempt to inject malicious parameters.
    * **Focus:** Assert that the model is updated only with the expected attributes and that sensitive attributes remain unchanged.
    * **Example (using RSpec with Hanami):**

    ```ruby
    # spec/web/controllers/users/update_spec.rb
    RSpec.describe Web::Controllers::Users::Update, type: :action do
      let(:user) { UserRepository.new.create(name: 'Original Name', email: 'original@example.com', is_admin: false) }
      let(:params) { { id: user.id, user: { name: 'New Name', email: 'new@example.com', is_admin: true } } }

      it 'updates allowed attributes' do
        response = subject.call(params)
        expect(response).to be_successful

        updated_user = UserRepository.new.find(user.id)
        expect(updated_user.name).to eq 'New Name'
        expect(updated_user.email).to eq 'new@example.com'
      end

      it 'ignores disallowed attributes' do
        response = subject.call(params)
        expect(response).to be_successful

        updated_user = UserRepository.new.find(user.id)
        expect(updated_user.is_admin).to be false # Ensure is_admin remains false
      end
    end
    ```

* **Security Audits and Penetration Testing:**
    * **Technique:** Engage security professionals to conduct thorough audits and penetration tests of the application.
    * **Focus:** Identify potential vulnerabilities that might have been missed during development and testing.

**8. Conclusion**

Mass assignment vulnerabilities pose a significant risk to Hanami applications due to the framework's direct interaction with request parameters and the lack of built-in strong parameter features. Developers must be vigilant in implementing robust mitigation strategies, including strong parameter patterns, attribute whitelisting, use case specific updates, and thorough input validation. Combining these technical safeguards with secure coding practices, code reviews, and comprehensive testing is essential to protect Hanami applications from this common and potentially damaging attack vector. By understanding the mechanics of mass assignment and adopting a proactive security mindset, development teams can build more secure and resilient Hanami applications.
