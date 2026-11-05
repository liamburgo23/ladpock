import json
from db import db


def lambda_handler(event, context):
    db.refunds.insert({"order": json.loads(event["body"])["order"]})
    return {"statusCode": 201}
