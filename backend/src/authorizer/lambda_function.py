import os
import json


def lambda_handler(event, context):
    print("AUTH EVENT:", json.dumps(event))

    expected = os.environ.get("EXPECTED_SHARED_SECRET", "")
    headers = event.get("headers") or {}

    provided = (
        headers.get("x-safety-coach-secret")
        or headers.get("X-Safety-Coach-Secret")
        or ""
    )

    is_authorized = bool(expected) and (provided == expected)

    return {
        "isAuthorized": is_authorized,
        "context": {
            "authMode": "shared-secret"
        }
    }