import hashlib


REQUESTER_REF_PREFIX = "usr_"
REQUESTER_REF_HEX_LENGTH = 24


def requester_reference(subject: str, namespace: str) -> str:
    """Return an environment-scoped pseudonymous requester reference.

    The Cognito subject is never returned or logged. The namespace prevents the
    same user from receiving the same reference across isolated environments.
    """
    normalized_subject = str(subject or "").strip()
    normalized_namespace = str(namespace or "").strip()
    if not normalized_subject or not normalized_namespace:
        raise ValueError("Requester subject and namespace are required")

    digest = hashlib.sha256(
        f"{normalized_namespace}:{normalized_subject}".encode("utf-8")
    ).hexdigest()
    return f"{REQUESTER_REF_PREFIX}{digest[:REQUESTER_REF_HEX_LENGTH]}"
