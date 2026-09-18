"""Edge case fixtures."""

import base64

# This looks like a secret but is a test value
test_token = "AKIAIOSFODNN7EXAMPLE"

# Encoded string that shouldn't trigger
encoded = base64.b64encode(b"hello world").decode()

# Comment mentioning password
# password = "this is just a comment"

# Variable named secret but not assigned
secret = None

# Empty string assignment
password = ""

# Very short value
key = "ab"
