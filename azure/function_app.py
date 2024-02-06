import azure.functions as func
import logging
import json
import os
import base64
import hashlib
import requests
import time
from datetime import datetime, timedelta
from azure.keyvault.secrets import SecretClient
from azure.keyvault.keys import KeyClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm

app = func.FunctionApp()
cache = {}

@app.function_name(name="eventGridTrigger")
@app.event_grid_trigger(arg_name="event")
def eventGridFunction(event: func.EventGridEvent):
    #CloudEvent schema
    cloudevent = [{
        'specversion': '1.0',
        'id': event.id,
        'data': event.get_json(),
        'source': event.topic,
        'subject': event.subject,
        'type': event.event_type,
        'time': event.event_time.isoformat(sep='T', timespec='auto')
    }]
    logging.info('CloudEvent:  %s', json.dumps(cloudevent))
    cdp_access_token, instance_url = _get_token_and_instance_url()

    beacon_url='https://' + instance_url +'/api/v1/unstructuredIngest?sourceType=azure'
    beacon_header = {'Authorization': 'Bearer ' + cdp_access_token, 'Content-Type': 'application/json'}
    beacon_response = requests.post(beacon_url, headers=beacon_header, json=cloudevent)
    beacon_response.raise_for_status()
    logging.info('Beacon Response - %s', str(beacon_response.json()))

def _get_token_and_instance_url():
    current_epoch = int(time.time())
    # Cache Hit
    if cache.get('cdp_access_token') and current_epoch < cache.get('cdp_access_token').get('ttl'):
        ttl = cache.get('cdp_access_token').get('ttl')
        logging.info("Cache hit! - token expiring in " + str(ttl - int(time.time())) + " seconds")
        return cache.get('cdp_access_token').get('token'), cache.get('cdp_access_token').get('instance_url')
    # Cache Miss
    else:
        jwt_token, expiry = _get_jwt()
        logging.info('JWT: %s', str(jwt_token))

        instance_url = os.environ['SF_LOGIN_URL'] + '/services/oauth2/token'
        data = {'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer', 'assertion': jwt_token}
        core_response = requests.post(instance_url, data=data)
        core_response.raise_for_status()
        logging.info('Response core access token - %s', str(core_response.json()))

        core_access_token = core_response.json()['access_token']
        core_instance_url = core_response.json()['instance_url']
        cdp_data = {'grant_type': 'urn:salesforce:grant-type:external:cdp',
                    'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
                    'subject_token': core_access_token}
        cdp_token_path = '/services/a360/token'
        cdp_url = core_instance_url + cdp_token_path
        cdp_response = requests.post(cdp_url, data=cdp_data)
        cdp_response.raise_for_status()
        logging.info('Response cdp access token - %s', str(cdp_response.json()))
        cdp_access_token = cdp_response.json()['access_token']
        instance_url = cdp_response.json()['instance_url']
        cache['cdp_access_token'] = {'token': cdp_access_token, 'ttl': expiry, 'instance_url': instance_url}
        return cdp_access_token, instance_url

def _get_jwt():
    credential = DefaultAzureCredential()
    crypto_client = _get_crypto_client(credential)
    vault_secret_client = _get_key_vault_secret_client(credential)
    #Headers
    headers_b64encoded = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode('utf-8'))
    #Payload
    due_date = datetime.now() + timedelta(hours=1)
    iss = vault_secret_client.get_secret('CONSUMER-KEY').value
    sub = os.environ['SF_USERNAME']
    aud = os.environ['SF_LOGIN_URL']
    expiry = int(due_date.timestamp())
    payload = {"iss": iss, "sub": sub, "exp": expiry, "aud": aud}
    payload_b64encoded = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8'))
    #Signature
    jwt_token = str(headers_b64encoded, 'utf-8') + '.' + str(payload_b64encoded, 'utf-8')
    jwt_token = jwt_token.replace('=', '')
    md = hashlib.sha256(jwt_token.encode('utf-8'))
    digest = md.digest()
    result = crypto_client.sign(SignatureAlgorithm.rs256, digest)
    sign_b64encoded = base64.urlsafe_b64encode(result.signature)

    jwt_token = jwt_token + '.' + str(sign_b64encoded, 'utf-8')
    return jwt_token.replace('=', ''), expiry

def _get_key_vault_secret_client(credential):
    keyVaultName = os.environ["KEY_VAULT_NAME"]
    KVUri = f"https://{keyVaultName}.vault.azure.net"
    return SecretClient(vault_url=KVUri, credential=credential)

def _get_crypto_client(credential):
    keyVaultName = os.environ["KEY_VAULT_NAME"]
    KVUri = f"https://{keyVaultName}.vault.azure.net"
    key_client = KeyClient(vault_url=KVUri, credential=credential)
    rsa_key = key_client.get_key('RSA-PRIVATE-KEY')
    return CryptographyClient(rsa_key, credential=credential)
