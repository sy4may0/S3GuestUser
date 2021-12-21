import string
import secrets
import re

class S3Error(Exception):
    pass

class IAMError(Exception):
    pass

def passwordGenerator(size=12):
    chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
    chars += '!@#$%^&*()_+-=[]{}|'

    while True:   
       password = ''.join(secrets.choice(chars) for x in range(size))
       if (any(c.islower() for c in password)
             and any(c.isupper() for c in password)
             and any(c.isdigit() for c in password)
             and not re.match('^[a-zA-Z0-9]+$', password)):
          break
      
    return password

def buildResult(response, body={}, error={}):
    result = {
        "statusCode": response['ResponseMetadata']['HTTPStatusCode'],
        "body": body,
        "error": error
    }

    return result
