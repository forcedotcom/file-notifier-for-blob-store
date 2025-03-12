# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import base64
import jwt
import requests
import logging
import time
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


logger = logging.getLogger()
logger.setLevel(logging.INFO)

cache = {}

def s3_events_handler(event, context):
    logging.info("S3 event: %s", json.dumps(event))
    cdp_access_token, instance_url = _get_token_and_instance_url()

    beacon_url = 'https://' + instance_url + '/api/v1/unstructuredIngest?sourceType=aws'
    beacon_header = {'Authorization': 'Bearer ' + cdp_access_token, 'Content-Type': 'application/json'}
    beacon_response = requests.post(beacon_url, headers=beacon_header, json=event)
    beacon_response.raise_for_status()
    print('Beacon Response - ' + str(beacon_response.json()))

def _get_token_and_instance_url():
    current_epoch = int(time.time())
    if cache.get('cdp_access_token') and current_epoch < cache.get('cdp_access_token').get('ttl'):
        # Cache Hit
        ttl = cache.get('cdp_access_token').get('ttl')
        print("Cache hit! - token expiring in " + str(ttl - int(time.time())) + " seconds")
        return cache.get('cdp_access_token').get('token'), cache.get('cdp_access_token').get('instance_url')
    else:
        # Cache Miss
        jwt_token, expiry = _get_jwt()
        print('Cache miss! - JWT token generated successfully')
        instance_url = os.environ['SF_LOGIN_URL'] + '/services/oauth2/token'
        data = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': jwt_token}
        core_response = requests.post(instance_url, data=data)
        core_response.raise_for_status()
        print('Response core access token generated successfully')

        core_access_token = core_response.json()['access_token']
        core_instance_url = core_response.json()['instance_url']
        cdp_data = {'grant_type': 'urn:salesforce:grant-type:external:cdp',
                    'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
                    'subject_token': core_access_token}
        cdp_token_path = '/services/a360/token'
        cdp_url = core_instance_url + cdp_token_path
        cdp_response = requests.post(cdp_url, data=cdp_data)
        cdp_response.raise_for_status()
        print('Response cdp access token generated successfully')
        cdp_access_token = cdp_response.json()['access_token']
        instance_url = cdp_response.json()['instance_url']
        cache['cdp_access_token'] = {'token': cdp_access_token, 'ttl': expiry, 'instance_url': instance_url}
        return cdp_access_token, instance_url

def _get_jwt():
    key = _get_rsa_key()
    key = key.splitlines()
    stripped_key = (''.join(i for i in key[1:-1])).strip()
    secret = base64.b64decode(stripped_key)
    due_date = datetime.now() + timedelta(minutes=50)
    iss = _get_consumer_key()
    sub = os.environ['SF_USERNAME']
    aud = os.environ.get('SF_AUDIENCE_URL', os.environ['SF_LOGIN_URL'])
    expiry = int(due_date.timestamp())
    payload = {"iss": iss, "sub": sub, "exp": expiry, "aud": aud}
    print(json.dumps(payload))
    priv_rsakey = serialization.load_der_private_key(secret, password=None, backend=default_backend())
    token = jwt.encode(payload, priv_rsakey, algorithm='RS256')
    return token, expiry


def _get_rsa_key():
    secret_id = os.environ.get('RSA_PRIVATE_KEY', 'RSA_PRIVATE_KEY')
    return _access_secret(secret_id)


def _get_consumer_key():
    secret_id = os.environ.get('CONSUMER_KEY', 'CONSUMER_KEY')
    return _access_secret(secret_id)


def _access_secret(secret_id: str) -> str:
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager')
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_id
        )
    except ClientError as e:
        raise e
    return get_secret_value_response['SecretString']