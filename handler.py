"""
    handler.py contains the Lambda entry point into the GitHub SecGroup Updater
"""
import os

import boto3
import botocore.exceptions

from secgrp_updater.main import run

STAGE = os.environ['STAGE']
PARAM_BASE = f'/github_secgrp_updater/{STAGE}'


def handle(event, _ctxt):
    """ Handle the Lambda Invocation """

    response = {
        'message': '',
        'event': event
    }

    ssm = boto3.client('ssm')
    vpc_ids = ssm.get_parameter(Name=f'{PARAM_BASE}/vpc_ids')['Parameter']['Value']
    vpc_ids = vpc_ids.split(',')

    args = {
        'vpc_ids': vpc_ids
    }

    try:
        sg_name = ssm.get_parameter(Name=f'{PARAM_BASE}/secgrp_name')['Parameter']['Value']
        args['managed_sg_name'] = sg_name
    except botocore.exceptions.ClientError as ex:
        if ex.response['Error']['Code'] == 'ParameterNotFound':
            pass
        else:
            print(ex)
            return response

    run(**args)

    return response
