# -*- coding: utf-8 -*-
from typing import Any, Dict, List

from chaosaws import aws_client
from chaosaws.types import AWSResponse
from chaoslib.types import Configuration, Secrets
from chaoslib.exceptions import FailedActivity
from logzero import logger
import boto3
import paramiko
import pickle
import json
import os



__all__ = ["describe_instances", "count_instances", "instance_state", "ssh_test"]


def ssh_test(pem_file_path: str = None):


    ec2 = boto3.resource('ec2')
    instance = None

    if os.path.exists("exp_data1.txt"):
        with open("exp_data1.txt", 'rt') as f:
            d2 = json.load(f)
    else :
        instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])

        for i in instances:
            instance = i
        instance_json = {
            'instance_id': instance.instance_id,
        }
        json.dump(instance_json, open("exp_data1.txt", 'w'))
        d2 = json.load(open("exp_data1.txt"))
        # print(d2)

    # if d2["instance_id"] == "" :
    #     print("instance is ----- empty")
    #
    # else :
    instance = ec2.Instance(d2["instance_id"])

    logger.info('Starting SSH into ec2 instance - ' + instance.instance_id)


    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    privkey = paramiko.RSAKey.from_private_key_file(pem_file_path)

    try :
        ssh.connect(instance.public_dns_name, username='ec2-user', pkey=privkey, timeout=10)
    except :
        logger.info('SSH Times out - waited for 10 seconds')
        return False

    stdin, stdout, stderr = ssh.exec_command('echo "hello world"')
    # stdin, stdout, stderr = ssh.exec_command('stress-ng --cpu 4 --timeout 60s --metrics-brief')
    stdin.flush()
    data = stdout.read().splitlines()
    for line in data:
        x = line.decode()

        ssh.close()

    logger.info('SSH Successfull')
    return True


def describe_instances(filters: List[Dict[str, Any]],
                       configuration: Configuration = None,
                       secrets: Secrets = None) -> AWSResponse:
    """
    Describe instances following the specified filters.

    Please refer to https://bit.ly/2Sv9lmU

    for details on said filters.
    """  # noqa: E501
    client = aws_client('ec2', configuration, secrets)

    return client.describe_instances(Filters=filters)


def count_instances(filters: List[Dict[str, Any]],
                    configuration: Configuration = None,
                    secrets: Secrets = None) -> int:
    """
    Return count of instances matching the specified filters.

    Please refer to https://bit.ly/2Sv9lmU

    for details on said filters.
    """  # noqa: E501
    client = aws_client('ec2', configuration, secrets)
    result = client.describe_instances(Filters=filters)

    return len(result['Reservations'])


def instance_state(state: str,
                   instance_ids: List[str] = None,
                   filters: List[Dict[str, Any]] = None,
                   configuration: Configuration = None,
                   secrets: Secrets = None) -> bool:
    """
    Determines if EC2 instances match desired state

    For additional filter options, please refer to the documentation found:
    https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
    """
    client = aws_client('ec2', configuration, secrets)

    if not any([instance_ids, filters]):
        raise FailedActivity('Probe "instance_state" missing required '
                             'parameter "instance_ids" or "filters"')

    if instance_ids:
        instances = client.describe_instances(InstanceIds=instance_ids)
    else:
        instances = client.describe_instances(Filters=filters)

    for i in instances['Reservations'][0]['Instances']:
        if i['State']['Name'] != state:
            return False
    return True
