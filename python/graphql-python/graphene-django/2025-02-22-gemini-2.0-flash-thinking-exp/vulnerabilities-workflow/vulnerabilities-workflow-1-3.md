### Vulnerability List

- Vulnerability Name: GraphQL Mutation Mass Assignment

- Description:
  The `IntroduceShip` mutation in the provided Star Wars example schema directly uses input values (`ship_name`, `faction_id`) to create a new `Ship` object without any input validation or sanitization.
  Step-by-step to trigger:
    1. Access the publicly available GraphQL endpoint of the application.
    2. Craft a GraphQL mutation query targeting the `introduceShip` mutation.
    3. In the mutation query, provide arbitrary values for `shipName` and `factionId` input fields. For example, include special characters, excessively long strings, or data in unexpected formats.
    4. Send the crafted mutation query to the GraphQL endpoint.
    5. Observe that a new `Ship` object is created in the database with the provided, potentially malicious or unexpected, data.

- Impact:
  Data integrity issues. In a more complex application, this vulnerability could allow an attacker to modify unintended fields of a model through GraphQL mutations. This can lead to data corruption, unauthorized data manipulation, or privilege escalation if model fields control access or permissions. Even in this example, while the impact is limited, it demonstrates a lack of input validation which is a security concern.

- Vulnerability Rank: High

- Currently implemented mitigations:
  None. The provided code example for `IntroduceShip` mutation directly creates a `Ship` object from input parameters without any validation.

- Missing mitigations:
  Input validation and sanitization should be implemented within the `mutate_and_get_payload` method of the `IntroduceShip` mutation.
    - **Input Validation:** Validate that `faction_id` corresponds to an existing `Faction` object. Validate the format and length of `ship_name` to ensure it meets expected criteria (e.g., prevent excessively long names or injection of special characters if not intended). Consider leveraging Django forms for structured input validation, especially when using `DjangoModelFormMutation`.
    - **Authorization:** Implement authorization checks to ensure that the user performing the mutation has the necessary permissions to create a `Ship` object and associate it with a `Faction`.
    - **Field Whitelisting (in more complex scenarios):** If the `Ship` model had more fields, implement explicit whitelisting to only allow modification of intended fields through the mutation, preventing attackers from manipulating other sensitive fields via mass assignment.

- Preconditions:
    - The GraphQL API endpoint is publicly accessible.
    - The GraphQL schema exposes mutations (like `introduceShip`) that create or update Django models.
    - These mutations directly use input values to create or update model instances without sufficient validation or sanitization.

- Source code analysis:
  File: `/code/examples/starwars/schema.py`

  ```python
  class IntroduceShip(relay.ClientIDMutation):
      class Input:
          ship_name = graphene.String(required=True)
          faction_id = graphene.String(required=True)

      ship = graphene.Field(Ship)
      faction = graphene.Field(Faction)

      @classmethod
      def mutate_and_get_payload(
          cls, root, info, ship_name, faction_id, client_mutation_id=None
      ):
          ship = create_ship(ship_name, faction_id) # [Vulnerable Code] Direct model creation without input validation
          faction = get_faction(faction_id)
          return IntroduceShip(ship=ship, faction=faction)
  ```

  File: `/code/examples/starwars/data.py`

  ```python
  def create_ship(ship_name, faction_id):
      new_ship = Ship(name=ship_name, faction_id=faction_id) # [Vulnerable Code] Direct attribute assignment from input
      new_ship.save()
      return new_ship
  ```

  **Visualization:**

  ```
  [GraphQL Client] --> Mutation Request (shipName="<script>...", factionId="1") --> [GraphQLView] --> IntroduceShip.mutate_and_get_payload()
                                                                                                  |
                                                                                                  V
                                                                                           create_ship(ship_name, faction_id) --> [Ship Model Creation] --> [Database]
  ```

  **Explanation:**

  1. The attacker sends a GraphQL mutation request to the `introduceShip` endpoint with crafted input values for `shipName` and `factionId`.
  2. The `GraphQLView` processes the request and calls the `mutate_and_get_payload` method of the `IntroduceShip` mutation.
  3. Inside `mutate_and_get_payload`, the `create_ship` function is called, which directly uses the `ship_name` and `faction_id` from the input to instantiate a `Ship` model object.
  4. The `Ship` object is saved to the database without any validation of the input data.
  5. This direct assignment from input to model fields without validation is the root cause of the Mass Assignment vulnerability.

- Security test case:
  1. **Setup:** Deploy the `graphene-django` example project (starwars). Ensure the GraphQL endpoint is accessible.
  2. **Craft Malicious Mutation Query:** Prepare a GraphQL mutation query to call `introduceShip` with a potentially malicious `shipName` and a valid `factionId`.

     ```graphql
     mutation IntroduceMaliciousShip {
       introduceShip(input:{clientMutationId:"test", shipName: "Malicious Ship <script>alert('XSS')</script>", factionId: "1"}) {
         ship {
           id
           name
         }
         faction {
           name
         }
       }
     }
     ```

  3. **Execute Mutation:** Send the crafted mutation query to the GraphQL endpoint using a tool like `curl`, `Postman`, or a GraphQL client in a browser (if GraphiQL is enabled).

     Example `curl` command:

     ```bash
     curl -X POST -H "Content-Type: application/json" -d '{"query": "mutation IntroduceMaliciousShip { introduceShip(input:{clientMutationId:\"test\", shipName: \"Malicious Ship <script>alert('XSS')</script>\", factionId: \"1\"}) { ship { id name } faction { name } } }"}' http://127.0.0.1:8000/graphql
     ```
     (Assuming the GraphQL endpoint is at `http://127.0.0.1:8000/graphql`)

  4. **Verify in Database:** Access the Django admin panel or use a database client to inspect the `starwars_ship` table. Check for the newly created `Ship` object. Verify that the `name` field of the newly created `Ship` contains the malicious string "Malicious Ship <script>alert('XSS')</script>".

  5. **Expected Result:** The `Ship` object should be successfully created in the database, and the `name` field should contain the injected malicious string. This confirms the Mass Assignment vulnerability as input is directly used to populate the model without validation. In a real application with more fields, this would indicate the potential to manipulate other fields as well if exposed in the mutation.