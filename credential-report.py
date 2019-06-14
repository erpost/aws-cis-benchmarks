from pprint import pprint

import boto3
import os


credentials = os.path.expanduser('.aws/credentials')
config = os.path.expanduser('.aws/config')

if os.path.isfile(credentials):
    os.environ['AWS_SHARED_CREDENTIALS_FILE'] = credentials
if os.path.isfile(config):
    os.environ['AWS_CONFIG_FILE'] = config


def generate_credential_report():
    client = boto3.client('iam')
    response = client.generate_credential_report()

    return response


def get_credential_report():
    client = boto3.client('iam')
    response = client.get_credential_report()

    return response


if __name__ == '__main__':
    generate_credential_report()
    pprint(get_credential_report())