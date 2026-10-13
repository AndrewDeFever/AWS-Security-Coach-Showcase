import json
import datetime

def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({
            "ok": True,
            "service": "aws-safety-coach",
            "route": "health",
            "time": datetime.datetime.utcnow().isoformat() + "Z"
        })
    }
