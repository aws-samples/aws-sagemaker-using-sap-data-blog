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
## 1. Replace <SAP Hostname>, <SAP Port Number>, <OData Service Name>, <OData Entity Name> and <Number of Entity> before using this script.
## 2. Create a secret in AWS Secret Manager called saponawsdemo
# ------------------------------------------------------------------

import boto3
import requests
from requests.auth import HTTPBasicAuth
import json
import os
import traceback
import copy
import uuid
import urllib3

sapHostName = "<SAP Hostname>"
sapPort = "<SAP Port Number>"
odpServiceName = "<SAP Odata service name>"
odpEntitySetName = "<SAP Odata entity set name>"
dataChunkSize = "1000"
dataS3Bucket='<Amazon S3 Bucket>'
dataS3Folder='<Amazon S3 Folder>'
selfSignedCertificate = ""
selfSignedCertificateS3Bucket = ""
selfSignedCertificateS3Key = ""
reLoad = False
_athenacompatiblejson = True
_allowInValidCerts = True
isInit = True
totalEntities = <Number of Entities>

# ------------------------
# Initialize
# ------------------------
def _setResponse(success,message, data, numberofrecs):
    response = {
        'success'   : success,
        'message'   : message,
        'copy'      : copy.format_exc(),
        'data'      : data,
        'numberofrecs' : numberofrecs
    }
    return response

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
# Perform extract
# ------------------------
def _extract(skip_key):
    global response
    
    skip_key=str(skip_key)
    url = _get_base_url() + "/" + odpEntitySetName + "?$format=json&$top=5000&$skip=" + skip_key
    print(url)
    
    headers = {
        "prefer" : "odata.maxpagesize=" + dataChunkSize + ",odata.track-changes"
    }
    sapresponse =  _make_http_call_to_sap(url,headers)
    sapresponsebody = json.loads(sapresponse.text)
    _response = copy.deepcopy(sapresponsebody)

    d = sapresponsebody.pop('d',None)
    results = d.pop('results',None)
    for result in results:
        _metadata = result.pop('__metadata',None)
    
    if len(results)<=0:
        response = _setResponse(True,"No data available to extract from SAP", _response, 0)
    elif(dataS3Bucket != ""):
        s3 = boto3.resource('s3')
        fileName = ''.join([dataS3Folder,'/',str(uuid.uuid4().hex[:6]),odpServiceName, "_", odpEntitySetName,".json"]) 
        object = s3.Object(dataS3Bucket, fileName)
        if _athenacompatiblejson==True:
            object.put(Body=_athenaJson(results))
        else:    
            object.put(Body=json.dumps(results,indent=4))
            
        response = _setResponse(True,"Data successfully extracted and stored in S3 Bucket with key " + fileName, None, len(results))
    else:
        response = _setResponse(True,"Data successfully extracted from SAP", _response, len(results))
        
# ------------------------------------
# Conver JSON to athena format
# ------------------------------------
def _athenaJson(objects):
    return '\n'.join(json.dumps(obj) for obj in objects)
    
# ------------------------------------
# Get base url for HTTP calls to SAP
# ------------------------------------
def _get_base_url():
    global sapPort
    if sapPort == "":
        sapPort = "50000"
    return "http://" + sapHostName + ":" + sapPort + "/sap/opu/odata/sap/" + odpServiceName
    
# ------------------------------------
# Call SAP HTTP endpoint
# ------------------------------------    
def _make_http_call_to_sap(url,headers):
    #global selfSignedCertificate
    certFileName = os.path.join('/tmp/','sapcert.crt')
    verify = True
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
    sapcred=json.loads(_get_secret())
    sapUser = sapcred["username"]
    sapPassword = sapcred["password"]
    return requests.get( url, headers=headers, auth=HTTPBasicAuth(sapUser,sapPassword), verify=verify)
    
# ------------------------------------
# Execute
# ------------------------------------  
x = 0
while (x < totalEntities ):
    _extract(x)
    x += 5000