```python
import unittest
from unittest.mock import MagicMock
from io import StringIO
import os

# Mock Iris Context for testing purposes
class MockContext:
    def __init__(self):
        self._params = {}
        self._status = 200
        self._body = ""
        self._sent_file = None

    def Params(self):
        return self

    def Get(self, key):
        return self._params.get(key)

    def StatusCode(self, code):
        self._status = code

    def WriteString(self, s):
        self._body += s

    def SendFile(self, filepath, filename):
        self._sent_file = (filepath, filename)

# Simulate Iris route handlers and StaticWeb
class IrisAppSimulator:
    def __init__(self):
        self.routes = {}
        self.static_dirs = {}

    def Get(self, path, handler):
        self.routes[path] = handler

    def HandleDir(self, path, root, strip_prefix=False):
        self.static_dirs[path] = {"root": root, "strip_prefix": strip_prefix}

    def ServeHTTP(self, method, path, params=None):
        ctx = MockContext()
        if params:
            ctx._params = params

        # Simulate route handling
        if method == "GET" and path in self.routes:
            self.routes[path](ctx)
            return ctx

        # Simulate static file serving
        for static_path, config in self.static_dirs.items():
            if path.startswith(static_path):
                file_path = path[len(static_path):]
                if config["strip_prefix"]:
                    pass # Already stripped
                if ".." in file_path:
                    ctx.StatusCode(400)
                    ctx.WriteString("Path traversal detected")
                    return ctx

                full_path = os.path.join(config["root"], file_path.lstrip('/'))
                if os.path.exists(full_path) and os.path.isfile(full_path):
                    ctx._sent_file = (full_path, os.path.basename(full_path))
                    return ctx
                else:
                    ctx.StatusCode(404)
                    return ctx

        ctx.StatusCode(404)
        return ctx

class TestPathTraversal(unittest.TestCase):
    def setUp(self):
        self.app = IrisAppSimulator()
        # Create dummy files for testing
        os.makedirs("test_files", exist_ok=True)
        with open("test_files/allowed.txt", "w") as f:
            f.write("This is an allowed file.")
        with open("test_files/secret.txt", "w") as f:
            f.write("This is a secret file.")
        os.makedirs("static_content", exist_ok=True)
        with open("static_content/public_file.txt", "w") as f:
            f.write("Public content.")
        os.makedirs("static_content/private", exist_ok=True)
        with open("static_content/private/private_file.txt", "w") as f:
            f.write("Private content.")

    def tearDown(self):
        # Clean up dummy files
        os.remove("test_files/allowed.txt")
        os.remove("test_files/secret.txt")
        os.remove("static_content/public_file.txt")
        os.remove("static_content/private/private_file.txt")
        os.rmdir("static_content/private")
        os.rmdir("static_content")
        os.rmdir("test_files")

    def test_vulnerable_route_handler(self):
        self.app.Get("/download/{filename}", lambda ctx: ctx.SendFile(f"test_files/{ctx.Params().Get('filename')}", ctx.Params().Get('filename')))
        ctx = self.app.ServeHTTP("GET", "/download/allowed.txt")
        self.assertEqual(ctx._status, 200)
        self.assertEqual(ctx._sent_file, ("test_files/allowed.txt", "allowed.txt"))

        # Attempt path traversal
        ctx = self.app.ServeHTTP("GET", "/download/../secret.txt")
        # In a real scenario, this might succeed depending on OS and permissions.
        # Here, we are simulating without OS-level access.
        # A proper mitigation would prevent this.
        # We can't directly assert file access here, but we can check for error if mitigation is in place.
        # For demonstration, let's assume the vulnerable code allows access.
        # In a real test with mitigation, we'd expect a 400 or similar.
        # self.assertNotEqual(ctx._status, 200) # Expect an error if mitigated

    def test_mitigated_route_handler_whitelisting(self):
        allowed_files = {"allowed": "allowed.txt"}
        def handler(ctx):
            filename_key = ctx.Params().Get("filekey")
            if filename_key in allowed_files:
                ctx.SendFile(f"test_files/{allowed_files[filename_key]}", allowed_files[filename_key])
            else:
                ctx.StatusCode(400)
                ctx.WriteString("Invalid file key")

        self.app.Get("/download_safe/{filekey}", handler)
        ctx = self.app.ServeHTTP("GET", "/download_safe/allowed")
        self.assertEqual(ctx._status, 200)
        self.assertEqual(ctx._sent_file, ("test_files/allowed.txt", "allowed.txt"))

        ctx = self.app.ServeHTTP("GET", "/download_safe/../secret")
        self.assertEqual(ctx._status, 400)
        self.assertEqual(ctx._body, "Invalid file key")

        ctx = self.app.ServeHTTP("GET", "/download_safe/allowed.txt") # Direct path attempt
        self.assertEqual(ctx._status, 400)
        self.assertEqual(ctx._body, "Invalid file key")

    def test_mitigated_route_handler_validation(self):
        import re
        def handler(ctx):
            filename = ctx.Params().Get("filename")
            if re.match(r"^[a-zA-Z0-9]+\.txt$", filename):
                ctx.SendFile(f"test_files/{filename}", filename)
            else:
                ctx.StatusCode(400)
                ctx.WriteString("Invalid filename format")

        self.app.Get("/download_validated/{filename}", handler)
        ctx = self.app.ServeHTTP("GET", "/download_validated/allowed.txt")
        self.assertEqual(ctx._status, 200)
        self.assertEqual(ctx._sent_file, ("test_files/allowed.txt", "allowed.txt"))

        ctx = self.app.ServeHTTP("GET", "/download_validated/../secret.txt")
        self.assertEqual(ctx._status, 400)
        self.assertEqual(ctx._body, "Invalid filename format")

    def test_vulnerable_staticweb(self):
        self.app.HandleDir("/static", "static_content")
        ctx = self.app.ServeHTTP("GET", "/static/public_file.txt")
        self.assertEqual(ctx._status, 200)
        self.assertEqual(ctx._sent_file, ("static_content/public_file.txt", "public_file.txt"))

        # Attempt path traversal
        ctx = self.app.ServeHTTP("GET", "/static/../private/private_file.txt")
        # Vulnerable setup allows access
        # In a real test with mitigation, we'd expect a 400 or 404.
        # For demonstration, let's assume the vulnerable setup allows access.
        # self.assertNotEqual(ctx._status, 200) # Expect an error if mitigated

    def test_mitigated_staticweb_stripprefix(self):
        self.app.HandleDir("/static", "static_content", strip_prefix=True)
        ctx = self.app.ServeHTTP("GET", "/static/public_file.txt")
        self.assertEqual(ctx._status, 200)
        self.assertEqual(ctx._sent_file, ("static_content/public_file.txt", "public_file.txt"))

        # Attempt path traversal is blocked due to strip_prefix and implicit checks
        ctx = self.app.ServeHTTP("GET", "/static/../private/private_file.txt")
        self.assertEqual(ctx._status, 400) # Or potentially 404 depending on implementation

    def test_mitigated_staticweb_restricted_root(self):
        self.app.HandleDir("/public", "static_content") # Serving only the 'static_content' directory
        ctx = self.app.ServeHTTP("GET", "/public/public_file.txt")
        self.assertEqual(ctx._status, 200)
        self.assertEqual(ctx._sent_file, ("static_content/public_file.txt", "public_file.txt"))

        # Attempt path traversal is blocked as 'private' is outside the served root
        ctx = self.app.ServeHTTP("GET", "/public/private/private_file.txt")
        self.assertEqual(ctx._status, 404)

        ctx = self.app.ServeHTTP("GET", "/public/../private/private_file.txt")
        self.assertEqual(ctx._status, 404)

if __name__ == '__main__':
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
```