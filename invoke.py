import os
import sys
import json
import boto3
import base64
import client.S3GuestUser
from jinja2 import Template, Environment, FileSystemLoader

ROOT = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PATH = ROOT + '/template'
NOTIFICATION_PATH = ROOT + '/notification_file'
QUERY_PATH = sys.argv[1]

LOGIN_LINK_FORMAT = "https://{0}.signin.aws.amazon.com/console"
DIR_LINK_FORMAT = \
    "https://s3.console.aws.amazon.com/s3/buckets/{0}?prefix={1}&region={2}"

if os.path.isfile(QUERY_PATH):
    with open(QUERY_PATH, 'r') as f:
        query = json.load(f)
else:
    print("ERROR: {0} is not found.".format(QUERY_PATH))
    exit(255)

if not os.path.isdir(NOTIFICATION_PATH):
    os.mkdir(NOTIFICATION_PATH)

result = client.S3GuestUser.handler(query)

print("---- QUERY RESULT ---------------------------")
print(json.dumps(result, indent=2))

if query['queryStringParameters']['action'] == 'create':
    user = result['create_iam_user']['create_user']['body']
    userName = user['userArn'].split('/')[1]
    loginProfile = result['create_iam_user']['create_login_profile']['body']
    password = loginProfile['password']
    account = result['meta']['account']['body']['aws_account']
    s3Bucket = result['meta']['s3_bucket']['body']['bucket']
    s3Region = result['meta']['s3_bucket']['body']['bucket_location']
    s3Url = result['create_object']['body']['s3_url']
    s3Prefix = s3Url.replace("s3://{0}/".format(s3Bucket), "")

    consoleLoginLink = LOGIN_LINK_FORMAT.format(account)
    dirLink = DIR_LINK_FORMAT.format(
        s3Bucket, s3Prefix, s3Region
    )

    env = Environment(loader=FileSystemLoader(TEMPLATE_PATH))
    template = env.get_template("user_notify_template.html.j2")

    data = {
        "account": account,
        "user": userName,
        "password": password,
        "console_link": consoleLoginLink,
        "dir_link": dirLink
    }

    html = template.render(data)

    notificationFilePath = "{0}/{1}_credentials.html".format(NOTIFICATION_PATH, userName)
    with open(notificationFilePath, 'w') as f:
        f.write(html)

    print("---- NOTIFICATION FILE ----------------------")
    print("PATH: " + notificationFilePath)
    print("")
