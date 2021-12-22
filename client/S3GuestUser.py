import json
import boto3
import os
import client.policy_template as policy_template
import base64
from client.utils import S3Error, IAMError
from client.utils import passwordGenerator, buildResult
from botocore.exceptions import ClientError

IAM_CHANGE_PASSWORD_POLICY_ARN = "arn:aws:iam::aws:policy/IAMUserChangePassword"

def getAccount():
    try:
        response = boto3.client('sts').get_caller_identity()
        account = response['Account']
        result = buildResult(
            response,
            body={ 'aws_account': account }
        )
    except ClientError as e:
        result = buildResult(
            e.response,
            error=e.response['Error']
        )

    return result
    
def getS3Region(bucket):
    try:
        response = boto3.client('sts').get_caller_identity()
        account = response['Account']
        response = boto3.client('s3').get_bucket_location(
            Bucket=bucket,
            ExpectedBucketOwner=account
        )

        result = buildResult(
            response,
            body={ 
                "bucket": bucket, 
                "bucket_location": response['LocationConstraint'] 
            }
        )
 
    except ClientError as e:
        result = buildResult(
            e.response,
            error=e.response['Error']
        )

    return result
 


# Create S3 Object.
def createS3Object(bucket, key):
    s3 = boto3.client('s3')
    objectList = s3.list_objects(Bucket=bucket, Prefix=key)
    if "Contents" in objectList:
        raise S3Error("S3 Object {0}/{1} exists.".format(bucket, key))

    response = s3.put_object(
        Bucket=bucket,
        Key=key
    )

    return buildResult(
        response, 
        body={"s3_url": "s3://{0}/{1}".format(bucket, key)},
    ) 

# Delete S3 Object forcedly.
def deleteS3Object(bucket, key):
    s3 = boto3.resource('s3')

    try:
        bucketRes = s3.Bucket(bucket)
        response = bucketRes.objects.filter(Prefix=key).delete()
        result = []
        for res in response:
            result.append(
                buildResult(
                    res,
                    body={"deleted": res['Deleted']}

                )
            )

    except ClientError as e:
        result = buildResult(
            e.response,
            error=e.response['Error']
        )
    
    return result
 

# Create IAM User and initialize login profile with init password.
def createIAMUser(user, group, dn, alias):
    resultSummary = {}
    iam = boto3.client('iam')

    # Create User.
    result = iam.create_user(
        Path='/',
        UserName=user,
        Tags=[
            { "Key": "dn", "Value": dn },
            { "Key": "alias", "Value": alias }
        ]
    )

    resultSummary['create_user'] = buildResult(
        result,
        body={
            "userArn": result['User']['Arn'],
            "userId": result['User']['UserId'],
            "alias": base64.b64encode(alias.encode()).decode()
        }
    )

    # Add user to group.
    result = iam.add_user_to_group(
        GroupName=group,
        UserName=user
    )

    resultSummary['add_to_group'] = buildResult(
        result,
        body={
            "group": group
        }
    )


    # Configure login profile.
    password = passwordGenerator()
    result = iam.create_login_profile(
        UserName=user,
        Password=password,
        PasswordResetRequired=True
    )

    resultSummary['create_login_profile'] = buildResult(
        result,
        body={
            "password": base64.b64encode(password.encode()).decode()
        }
    )


    return resultSummary

# Delete IAM User forcedly.
def deleteIAMUser(user, group):
    resultSummary={}
    iam = boto3.client('iam')

    # Delete login profile.
    try:
        result = iam.delete_login_profile(
            UserName=user,
        )

        resultSummary['delete_login_profile'] = buildResult(
            result
        )

    except ClientError as e:
        resultSummary['delete_login_profile'] = buildResult(
            e.response,
            error=e.response['Error']
        )

    # Remove user from group.
    try:
        result = iam.remove_user_from_group(
            GroupName=group,
            UserName=user
        )

        resultSummary['remove_from_group'] = buildResult(
            result
        )
 
    except ClientError as e:
        resultSummary['remove_from_group'] = buildResult(
            e.response,
            error=e.response['Error']
        )

    # Delete User
    try:
        result = iam.delete_user(
            UserName=user
        )

        resultSummary['delete_user'] = buildResult(
            result
        )

    except ClientError as e:
        resultSummary['delete_user'] = buildResult(
            e.response,
            error=e.response['Error']
        )

    return resultSummary

# Create IAM Policy and attach to user.
def createIAMPolicy(user, dn, bucket):
    resultSummary={}
    iam = boto3.client('iam')

    # Create Policy.
    policy = policy_template.get()
    policy['Statement'][0]['Resource'] = "arn:aws:s3:::" + bucket
    policy['Statement'][0]['Condition']['StringLike']['s3:prefix'] = \
            [ "{0}/{1}/*".format(dn, user) ]
    policy['Statement'][1]['Resource'] = \
            "arn:aws:s3:::{0}/{1}/{2}/*".format(bucket, dn, user)

    policyDump = json.dumps(policy)
    result = iam.create_policy(
        PolicyName="s3-ro-" + user,
        PolicyDocument=policyDump
    )
    policyArn = result['Policy']['Arn']
    resultSummary['create_policy'] = buildResult(
        result,
        body={ "policyArn": policyArn }
    )

    # Attach S3 Policy.
    result = iam.attach_user_policy(
        PolicyArn=policyArn,
        UserName=user
    )
    resultSummary['attach_s3_policy'] = buildResult(
        result,
    )

    # Attach S3 Policy.
    result = iam.attach_user_policy(
        PolicyArn=IAM_CHANGE_PASSWORD_POLICY_ARN,
        UserName=user
    )
    resultSummary['attach_password_policy'] = buildResult(
        result,
    )

    return resultSummary

# Delete IAM Policy
def deleteIAMPolicy(user):
    resultSummary={}
    iam = boto3.client('iam')
    try:
        identity = boto3.client('sts').get_caller_identity()
        account = identity['Account']
        policyArn = "arn:aws:iam::{0}:policy/s3-ro-{1}".format(account, user)
    except ClientError as e:
        resultSummary['get_account'] = buildResult(
            e.response,
            error=e.response['Error']
        )
        return resultSummary

    # detach S3 Policy.
    try:
        result = iam.detach_user_policy(
            PolicyArn=policyArn,
            UserName=user
        )

        resultSummary['detach_s3_policy'] = buildResult(
            result
        )

    except ClientError as e:
        resultSummary['detach_s3_policy'] = buildResult(
            e.response,
            error=e.response['Error']
        )

    # Detach S3 Policy.
    try:
        result = iam.detach_user_policy(
            PolicyArn=IAM_CHANGE_PASSWORD_POLICY_ARN,
            UserName=user
        )

        resultSummary['detach_password_policy'] = buildResult(
            result,
        )


    except ClientError as e:
        resultSummary['detach_password_policy'] = buildResult(
            e.response,
            error=e.response['Error']
        )

    # Delete Policy
    try:
        result = iam.delete_policy(
            PolicyArn=policyArn
        )

        resultSummary['delete_policy'] = buildResult(
            result,
        )

    except ClientError as e:
        resultSummary['delete_policy'] = buildResult(
            e.response,
            error=e.response['Error']
        )

    return resultSummary

def handler(event):
    parameters = event['queryStringParameters']

    user = parameters['user']
    group = parameters['group']
    dn = parameters['dn']
    alias = parameters['alias']
    bucket = parameters['bucket']
    objectKey = parameters['dn'] + '/' + parameters['user'] + '/'
    action = parameters['action']

    result = {}
    result['meta'] = {
        "account" : getAccount(),
        "s3_bucket" : getS3Region(bucket)
    }
    if action == 'create':
        result['create_object'] = createS3Object(bucket, objectKey)
        result['create_iam_user'] = createIAMUser(user, group, dn, alias)
        result['create_iam_policy'] = createIAMPolicy(user, dn, bucket)
        result['statusCode'] = 200 
    elif action == 'delete':
        result['delete_object'] = deleteS3Object(bucket, objectKey)
        result['delete_iam_user'] = deleteIAMPolicy(user)
        result['delete_iam_policy'] = deleteIAMUser(user, group)
        result['statusCode'] = 200 
    else:
        result = {
            "statusCode": 500,
            "error": "Invalid action."
        }

    return result