import boto3


CUSTOMER_GROUP = "customer"
CONFIRM_SIGNUP_TRIGGER = "PostConfirmation_ConfirmSignUp"

cognito = boto3.client("cognito-idp")


def lambda_handler(event, context):
    """Assign newly confirmed self-signups to the customer Cognito group.

    Password-reset confirmations intentionally do not change authorization. The
    group name is fixed server-side so trigger input cannot select a privileged
    group.
    """
    if str(event.get("triggerSource", "")).strip() != CONFIRM_SIGNUP_TRIGGER:
        return event

    user_pool_id = str(event.get("userPoolId", "")).strip()
    username = str(event.get("userName", "")).strip()
    if not user_pool_id or not username:
        raise ValueError("Post-confirmation event is missing Cognito identity")

    cognito.admin_add_user_to_group(
        UserPoolId=user_pool_id,
        Username=username,
        GroupName=CUSTOMER_GROUP,
    )
    print("Confirmed signup assigned to customer group")
    return event
