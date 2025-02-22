- Vulnerability Name: Insecure Node Move Operation in DraggableMPTTAdmin

  Description:
  An attacker can potentially move any node in the MPTT tree structure through the `_move_node` action in `DraggableMPTTAdmin` without proper authorization checks beyond basic `has_change_permission`. This is because the `_move_node` method in `DraggableMPTTAdmin` only checks `has_change_permission(request, cut_item)` for the node being moved (`cut_item`), but it does not perform any permission checks on the target node (`pasted_on`). If an attacker has change permissions on at least one node in the tree, they can potentially move any node in the tree structure by manipulating the `cut_item` and `pasted_on` parameters in the `move_node` request.

  Steps to trigger:
  1. Log in to the Django admin panel as a user who has change permissions for the MPTT model managed by `DraggableMPTTAdmin`.
  2. Identify two nodes in the MPTT tree: a node to be moved (`cut_item`) and a target node (`pasted_on`). Let's say `cut_item` has ID '1' and `pasted_on` has ID '2'.
  3. Craft a POST request to the admin changelist view URL of the MPTT model. The request should include the following parameters:
     - `cmd`: `move_node`
     - `cut_item`: ID of the node to be moved (e.g., '1')
     - `pasted_on`: ID of the target node (e.g., '2')
     - `position`: Desired position relative to the target node (e.g., 'last-child', 'left', 'right')
  4. Send the crafted POST request to the server.
  5. Observe that the node with ID '1' is moved to the specified position relative to the node with ID '2', even if the logged-in user does not have explicit change permissions for node '2'.

  Impact:
  Unauthorized modification of the MPTT tree structure. An attacker could arbitrarily restructure the tree, potentially leading to data integrity issues, disruption of application functionality that relies on the tree structure, and in some cases, information disclosure if the tree structure itself reveals sensitive information or access control bypass if tree structure is used for access control logic.

  Vulnerability Rank: High

  Currently Implemented Mitigations:
  - The `_move_node` function checks `if not self.has_change_permission(request, cut_item):` to ensure the user has change permission on the `cut_item`.

  Missing Mitigations:
  - Missing permission check for the `pasted_on` node. The system should verify that the logged-in user also has appropriate permissions to perform actions related to the `pasted_on` node, or at least ensure that moving `cut_item` to `pasted_on`'s location is within the user's allowed actions. Ideally, permissions should be checked for both `cut_item` and `pasted_on` to ensure that the user is authorized to modify both the node being moved and the target location in the tree.

  Preconditions:
  - Django application uses `DraggableMPTTAdmin` for managing an MPTT model in the admin panel.
  - An attacker has a valid Django admin account with change permissions for at least one instance of the MPTT model.

  Source Code Analysis:
  ```python
  File: /code/mptt/admin.py
  ...
  class DraggableMPTTAdmin(MPTTModelAdmin):
  ...
      @transaction.atomic
      def _move_node(self, request):
          position = request.POST.get("position")
          if position not in ("last-child", "left", "right"):
              self.message_user(
                  request,
                  _("Did not understand moving instruction."),
                  level=messages.ERROR,
              )
              return http.HttpResponse("FAIL, unknown instruction.")

          queryset = self.get_queryset(request)
          try:
              cut_item = queryset.get(pk=request.POST.get("cut_item"))
              pasted_on = queryset.get(pk=request.POST.get("pasted_on"))
          except (self.model.DoesNotExist, TypeError, ValueError):
              self.message_user(
                  request, _("Objects have disappeared, try again."), level=messages.ERROR
              )
              return http.HttpResponse("FAIL, invalid objects.")

          if not self.has_change_permission(request, cut_item): # Permission check only for cut_item
              self.message_user(request, _("No permission"), level=messages.ERROR)
              return http.HttpResponse("FAIL, no permission.")

          data_before_update = self.get_data_before_update(request, cut_item, pasted_on)

          try:
              self.model._tree_manager.move_node(cut_item, pasted_on, position)
          except InvalidMove as e:
              self.message_user(request, "%s" % e, level=messages.ERROR)
              return http.HttpResponse("FAIL, invalid move.")
          except IntegrityError as e:
              self.message_user(
                  request, _("Database error: %s") % e, level=messages.ERROR
              )
              raise

          change_message = self.get_move_node_change_message(
              request, cut_item, pasted_on, data_before_update
          )

          LogEntry.objects.log_action(
              user_id=request.user.pk,
              content_type_id=get_content_type_for_model(cut_item).pk,
              object_id=cut_item.pk,
              object_repr=str(cut_item),
              action_flag=CHANGE,
              change_message=change_message,
          )

          self.message_user(request, _("%s has been successfully moved.") % cut_item)
          return http.HttpResponse("OK, moved.")
  ```
  The code snippet shows that only `has_change_permission(request, cut_item)` is checked. There is no permission check performed for `pasted_on`.

  Security Test Case:
  1. Set up a Django project with an MPTT model and register it in `admin.py` using `DraggableMPTTAdmin`. Ensure there are at least two nodes in the tree.
  2. Create two Django admin users:
     - `user_a`: Grant 'change' permission only for one specific MPTT model instance (e.g., instance with pk=1). This can be done using Django's permission system, e.g., via object permissions or custom permission checks.
     - `user_b`: Grant 'change' permission for all MPTT model instances.
  3. Log in to the Django admin panel as `user_a`.
  4. In the MPTT model's changelist view, use browser developer tools to inspect the HTML and find the IDs of two nodes: `cut_item_id` (e.g., the node for which `user_a` has change permission, pk=1) and `pasted_on_id` (e.g., another node for which `user_a` does *not* have explicit change permission, pk=2).
  5. Craft a POST request using `curl` or a similar tool, sending it to the MPTT model's changelist URL:
     ```bash
     curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "cmd=move_node&cut_item=cut_item_id&pasted_on=pasted_on_id&position=last-child&csrfmiddlewaretoken=YOUR_CSRF_TOKEN&_changelist_filters=_changelist_filters" http://your-django-admin-url/your_mptt_model/
     ```
     Replace `cut_item_id`, `pasted_on_id`, `YOUR_CSRF_TOKEN`, and `http://your-django-admin-url/your_mptt_model/` with the actual values. You can get CSRF token from the admin page's source code.
  6. After sending the request, refresh the admin changelist view in the browser (logged in as `user_a`).
  7. Verify that the node with `cut_item_id` has been moved under or near the node with `pasted_on_id`.
  8. Log in as `user_b` and verify that the move action is also logged in the admin action logs for the `cut_item` node.

  This test case will demonstrate that `user_a`, who only has change permission for `cut_item`, can successfully move it relative to `pasted_on`, even if they don't have explicit permissions for `pasted_on`, confirming the vulnerability.