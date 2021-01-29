"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

# ------------------------------------------------------------------
## This code is a fork of https://github.com/aws-samples/aws-lambda-sap-odp-extractor
## This extract data using the Python requests library.
## Prerequisite 
## 1. Replace <SAP Hostname>, <SAP Port Number>, <OData Service Name>, <OData Entity Name>, <Number of Entity>, <Amazon S3 bucket name>, <Amazon S3 folder name> and <Amazon S3 object name> before using this script.
## 2. Create a secret in AWS Secret Manager called saponawsdemo
# ------------------------------------------------------------------

import boto3
import requests
import json
from requests.auth import HTTPBasicAuth
import base64
from botocore.exceptions import ClientError

sapHostName = "<SAP Hostname>"
sapPort = "<SAP Port Number>"
odpServiceName = "<OData Service Name>"
odpEntitySetName = "<OData Entity Name>"
dataS3Bucket = "<Amazon S3 bucket name>"
dataS3Folder = "<Amazon S3 folder name>"
dataS3name = "<Amazon S3 object name>"
totalEntities = <Number of Entries>
selfSignedCertificate = ""
selfSignedCertificateS3Bucket = ""
selfSignedCertificateS3Key = ""
reLoad = False
_allowInValidCerts = True
isInit = True


# ------------------------------------
# Get base url for HTTP calls to SAP
# ------------------------------------
def _get_base_url():
    global sapPort
    if sapPort == "":
        sapPort = "50000"
    return "http://" + sapHostName + ":" + sapPort + "/sap/opu/odata/sap/" + odpServiceName
    
# ------------------------------------
# Get Username and Password from Secret Manager
# ------------------------------------    
def _get_secret():

    secret_name = "saponawsdemo"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
    
    return(secret)
    
# ------------------------
# Perform import
# ------------------------

def _import_json():
    
    if selfSignedCertificate != "" :
        certfile = open(certFileName,'w')
        os.write(certfile,selfSignedCertificate)
        verify = certFileName
    elif selfSignedCertificateS3Bucket != "" :
        s3 = boto3.client('s3')
        verify = certFileName
        with open(certFileName, 'w') as f:
            s3.download_fileobj(selfSignedCertificateS3Bucket, selfSignedCertificateS3Key, f)
        certfile = open(certFileName,'r')
        print(certfile.read())
    elif _allowInValidCerts == True:
        verify = False

    # Retrieve the CSRF token first
    url = _get_base_url()
    session = requests.Session()
    response = session.head(url, auth=HTTPBasicAuth(sapUser,sapPassword), headers={'x-csrf-token': 'fetch'}, verify=verify)
    token = response.headers.get('x-csrf-token', '')

    # Execute Post request
    url = _get_base_url() + "/" + odpEntitySetName
    headers = { "Content-Type" : "application/json; charset=utf-8","X-CSRF-Token" : token }
    response =  session.post(url, auth=HTTPBasicAuth(sapUser,sapPassword), headers=headers, json=ijson, verify=verify)
    print(response)
    
# ------------------------
# Get data from Amazon S3
# ------------------------

def _get_data():
    
    file_to_read = dataS3Folder + '/' + dataS3name
    s3 = boto3.resource('s3')

    content_object = s3.Object(dataS3Bucket, file_to_read)
    file_content = content_object.get()['Body'].read().decode('utf-8')
    file_content = "[" + file_content + "]" 
    file_content = file_content.replace('\n', ',')
    file_content = file_content.replace(',]', ']')
    json_content = json.loads(file_content)
    
    return(json_content)
 
# ------------------------
# Start of Program
# ------------------------  

data_load=_get_data()
sapcred=json.loads(_get_secret())
sapUser = sapcred["username"]
sapPassword = sapcred["password"]

x = 1
while (x <= totalEntities):
    ijson = data_load
    _import_json()
    x += 1

