POLICY_TEMPLATE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": "",
            "Condition": {
                "StringLike": {
                    "s3:prefix": []
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject"
            ],
            "Resource": ""
        }
    ]
}

def get():
    return POLICY_TEMPLATE