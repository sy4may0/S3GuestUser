import os
import sys
import json
import boto3

ROOT = os.path.dirname(os.path.abspath(__file__))
QUERY_PATH = sys.argv[1]
LAMBDA_FUNCTION_NAME = 's3-guest-user'

if os.path.isfile(QUERY_PATH):
    with open(QUERY_PATH, 'r') as f:
        query = json.load(f)
else:
    print("ERROR: {0} is not found.".format(QUERY_PATH))
    exit(255)

client = boto3.client('lambda')

response = client.invoke(
    FunctionName=LAMBDA_FUNCTION_NAME,
    InvocationType='RequestResponse',
    LogType='Tail',
    Payload=json.dumps(query)
)

result = json.loads(response['Payload'].read().decode())

print(json.dumps(result, indent=2))
