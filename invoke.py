import os
import sys
import json
import boto3
import base64
import client.S3GuestUser

ROOT = os.path.dirname(os.path.abspath(__file__))
QUERY_PATH = sys.argv[1]
LAMBDA_FUNCTION_NAME = 's3-guest-user'

LOGIN_LINK_FORMAT = "https://{0}.signin.aws.amazon.com/console"
DIR_LINK_FORMAT = \
    "https://s3.console.aws.amazon.com/s3/buckets/{0}?prefix={1}&region={2}"

if os.path.isfile(QUERY_PATH):
    with open(QUERY_PATH, 'r') as f:
        query = json.load(f)
else:
    print("ERROR: {0} is not found.".format(QUERY_PATH))
    exit(255)

result = client.S3GuestUser.handler(query)

print(json.dumps(result, indent=2))

if query['queryStringParameters']['action'] == 'create':
    user = result['create_iam_user']['create_user']['body']
    loginProfile = result['create_iam_user']['create_login_profile']['body']
    account = result['meta']['account']['body']['aws_account']
    s3Bucket = result['meta']['s3_bucket']['body']['bucket']
    s3Region = result['meta']['s3_bucket']['body']['bucket_location']
    s3Url = result['create_object']['body']['s3_url']
    s3Prefix = s3Url.replace("s3://{0}/", "")

    userid = user['userArn'].split('/')[1]
    password = base64.b64decode(loginProfile['password'])
    loginLink = LOGIN_LINK_FORMAT.format(account)
    dirLink = DIR_LINK_FORMAT.format(
        s3Bucket, s3Prefix, s3Region
    )


    print("---- notify text ------------------")
    print("User ID,Password,Console Login Link,User Directory Link")
    print("{0},{1},{2},{3}".format(
        userid, 
        password.decode(),
        loginLink,
        dirLink
    ))
