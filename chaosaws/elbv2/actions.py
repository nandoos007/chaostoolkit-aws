# -*- coding: utf-8 -*-
import random
from typing import Dict, List

import boto3
import json
from botocore.exceptions import ClientError
from logzero import logger

from chaoslib.exceptions import FailedActivity
from chaoslib.types import Configuration, Secrets
from chaosaws import aws_client
from chaosaws.types import AWSResponse
import time
import random

__all__ = ["deregister_target", "set_security_groups", "set_subnets",
           "delete_load_balancer", "alb_instance_healthcheck_fail", 
           "deregister_instances", "register_instances"]


def get_client(service):
    """Get an AWS client for a service."""
    session = boto3.Session()
    return session.client(service)

def get_response(self, action, params, path='/', parent=None,
                 verb='POST', list_marker='Set'):
    """
    Utility method to handle calls to IAM and parsing of responses.
    """
    if not parent:
        parent = self
    response = self.make_request(action, params, path, verb)
    body = response.read()
    boto.log.debug(body)
    if response.status == 200:
        e = boto.jsonresponse.Element(list_marker=list_marker,
                                      pythonize_name=True)
        h = boto.jsonresponse.XmlHandler(e, parent)
        h.parse(body)
        return e
    else:
        boto.log.error('%s %s' % (response.status, response.reason))
        boto.log.error('%s' % body)
        raise self.ResponseError(response.status, response.reason, body)


def get_client(service):
    """Get an AWS client for a service."""
    session = boto3.Session()
    return session.client(service)


def get_load_balancers():
    """List info about all load balancers."""
    client = get_client("elbv2")
    return client.describe_load_balancers()

def create_dummy_certificate():
    # private_file = open("server.key", "rb").read()
    # public_file = open("server.crt", "rb").read()
    # cert = {}
    # cert['Key'] = "Name"
    # cert['Value'] = "AUTOCERT"
    #
    # Tags_Array =[]
    # Tags_Array.append(cert)
    #
    # client = boto3.client('acm')
    # response = client.import_certificate(Certificate = public_file, PrivateKey = private_file, Tags = Tags_Array )
    # print("NEW CERTIFICATE - " + response['CertificateArn'])

    client = boto3.client('iam')
    PrivateKey = open("server.key", "rb").read().decode()
    CertificateBody  = open("server.crt", "rb").read().decode()

    response = client.upload_server_certificate(
        ServerCertificateName ='AutoIAMCert6',
        CertificateBody = CertificateBody,
        PrivateKey = PrivateKey,
    )

    return response['ServerCertificateMetadata']['Arn']


def alb_certificate_removed() :

    dummy_certificate_arn = create_dummy_certificate()

    client = get_client("elbv2")
    lb = get_load_balancers()
    logger.info('Getting list of loadbalancers' + str(get_load_balancers()))

    for x in lb['LoadBalancers'] :
        logger.info('getting list of listners   ' + x['LoadBalancerArn'] )
        # Get Listeners
        logger.info('Describe Listeners ' + str(client.describe_listeners(LoadBalancerArn = x['LoadBalancerArn'])))
        listeners = client.describe_listeners(LoadBalancerArn = x['LoadBalancerArn'])
        j2 = {}
        listner_dict = {}
        listener_arr = []
        for y in listeners['Listeners'] :
            cert_arr = []
            logger.info('Listener configuration ' + str(y))
            try :
                if 'Certificates' in y.keys() :
                   j2['ListenerArn'] = y['ListenerArn']
                   for z in y['Certificates'] :
                        cert_dict = {}
                        cert_dict['CertificateArn'] = z['CertificateArn']
                        if 'IsDefault' in z.keys() :
                            cert_dict['IsDefault'] = z['IsDefault']
                        cert_arr.append(cert_dict)
                        j2['Certificates'] = cert_arr
                        listener_arr.append(j2)
            except Exception as ex:
                logger.info(ex)

        logger.info("Saving current certificate data")
        listner_dict['Listener'] = listener_arr
        json.dump(listner_dict, open("alb_certs_data.txt", 'w'))

        d2 = json.load(open("alb_certs_data.txt"))
        client = get_client("elbv2")
        cert = {}
        cert['CertificateArn'] = dummy_certificate_arn

        # cert['CertificateArn'] = "arn:aws:iam::317258752732:server-certificate/ExampleCertificate"
        cert_Array =[]
        cert_Array.append(cert)
        logger.infor("Attaching dummy certificate "+ str(cert_Array))

        for x in d2['Listener'] :
            time.sleep(20)
            client.modify_listener(ListenerArn = x['ListenerArn'], Certificates = cert_Array)

        time.pause(30)
        rollback_alb_certificate_removed()


def rollback_alb_certificate_removed() :
    Logger.info("------ ROLLING-BACK Certiifcate  -----")
    time.sleep(20)
    client = get_client("elbv2")
    d2 = json.load(open("alb_certs_data.txt"))
    for x in d2['Listener'] :
        client.modify_listener(ListenerArn = x['ListenerArn'], Certificates = x['Certificates'])
    time.sleep(20)
    iam = boto3.resource('iam')
    server_certificate = iam.ServerCertificate('AutoIAMCert6')
    server_certificate.delete()


def alb_listener_removed() :
    client = get_client("elbv2")
    loadBalancers = client.describe_load_balancers()
    exp_data={}

    lb_arn = None
    for lb in loadBalancers['LoadBalancers'] :
        lb_arn = lb['LoadBalancerArn']
        listeners = client.describe_listeners(LoadBalancerArn = lb_arn)
        exp_data = listeners
        exp_data['lb_arn'] = lb_arn
        json.dump(exp_data, open("alb_listeners_data.txt", 'w'))
        for ln in listeners['Listeners'] :
            logger.infor("Removing listner - " + ln['ListenerArn'])
            client.delete_listener(ListenerArn = ln['ListenerArn'])


def rollback_alb_listener_removed() :
    client = get_client("elbv2")
    d2 = json.load(open("alb_listeners_data.txt"))
    lb_arn = d2['lb_arn']

    for ln in d2['Listeners']:
        logger.info("Creating Listner  - "+ ln['Protocol'])
        client.create_listener(LoadBalancerArn = lb_arn, Protocol = ln['Protocol'] , Port = ln['Port'], DefaultActions = ln['DefaultActions'] )




def alb_instance_healthcheck_fail():

    client = get_client("elbv2")
    loadBalancers = client.describe_load_balancers()
    ec2 = boto3.resource('ec2')
    exp_data = {}

    lb_arn = None
    running_instances = None

    for lb in loadBalancers['LoadBalancers'] :
        lb_arn = lb['LoadBalancerArn']
        logger.info("LB ARN  - "+lb_arn )
        tg_list = client.describe_target_groups( LoadBalancerArn = lb_arn)
        logger.info ("Target List " +str(tg_list))
        for tg in tg_list['TargetGroups'] :
            tg_arn = tg['TargetGroupArn']
            tg_health_desc = client.describe_target_health( TargetGroupArn = tg_arn)
            for target in tg_health_desc['TargetHealthDescriptions'] :
                instance_id = target['Target']['Id']
                inst_list=[]
                inst_list.append(instance_id)
                exp_data['InstanceId'] = instance_id
                running_instances =  ec2.instances.filter(Filters=[{'Name': 'instance-state-name' , 'Values': ['running']}, {'Name': 'instance-id', 'Values': inst_list }])
                for instance in running_instances :
                    dummy_sg_id = create_dummy_sg(instance)
                    exp_data['ChaosSecurityGroupId'] = dummy_sg_id
                break
            break
        break

    all_sg_ids = []
    for instance in running_instances :
        exp_data['SecurityGroups'] = [sg['GroupId'] for sg in instance.security_groups]  # Get a list of ids of all securify groups attached to the instance
        all_sg_ids = []
        all_sg_ids.append(dummy_sg_id)
        logger.info("attaching dummy security group ")
        instance.modify_attribute(Groups=all_sg_ids)

    json.dump(exp_data, open("alb_sg_data.txt", 'w'))


def rollback_alb_instance_healthcheck_fail():
    ec2 = boto3.resource('ec2')
    d2 = json.load(open("alb_sg_data.txt"))
    inst_list=[]
    inst_list.append(d2['InstanceId'])
    running_instances =  ec2.instances.filter(Filters=[{'Name': 'instance-state-name' , 'Values': ['running']}, {'Name': 'instance-id', 'Values': inst_list }])
    for instance in running_instances :
        instance.modify_attribute(Groups=d2['SecurityGroups'])
    get_client("ec2").delete_security_group(GroupId=d2['ChaosSecurityGroupId'])




def create_dummy_sg(inst) :
    ec2 = boto3.client('ec2')
    response = ec2.create_security_group(GroupName='CHAOS_SECURITY_GROUP_7',
                                         Description='CHAOS SG GROUP',
                                         VpcId= inst.vpc_id)

    logger.info("Dummy Security Group  - " + response['GroupId'] )
    return response['GroupId']




def deregister_target(tg_name: str,
                      configuration: Configuration = None,
                      secrets: Secrets = None) -> AWSResponse:
    """Deregisters one random target from target group"""
    client = aws_client('elbv2', configuration, secrets)
    tg_arn = get_target_group_arns(tg_names=[tg_name], client=client)
    tg_health = get_targets_health_description(tg_arns=tg_arn, client=client)
    random_target = random.choice(
        tg_health[tg_name]['TargetHealthDescriptions'])

    logger.debug("Deregistering target {} from target group {}".format(
        random_target['Target']['Id'], tg_name))

    try:
        return client.deregister_targets(
            TargetGroupArn=tg_arn[tg_name],
            Targets=[{
                'Id': random_target['Target']['Id'],
                'Port': random_target['Target']['Port']
            }]
        )
    except ClientError as e:
        raise FailedActivity('Exception detaching %s: %s' % (
            tg_name, e.response['Error']['Message']))

def deregister_instances(tg_name: str,
                      configuration: Configuration = None,
                      secrets: Secrets = None) -> AWSResponse:
    d2 = json.load(open('exp_data1.txt'))
    """Deregisters all instances in exp_data1.txt"""
    client = aws_client('elbv2', configuration, secrets)
    tg_arn = get_target_group_arns(tg_names=[tg_name], client=client)
    tg_health = get_targets_health_description(tg_arns=tg_arn, client=client)
    instances = list(map(lambda instance: instance['Id'],d2['target_group']['instances']))

    logger.debug("Deregistering target {} from target group {}".format(
        instances, tg_name))

    try:
        return client.deregister_targets(
            TargetGroupArn=tg_arn[tg_name],
            Targets=d2['target_group']['instances']
        )
    except ClientError as e:
        raise FailedActivity('Exception detaching %s: %s' % (
            tg_name, e.response['Error']['Message']))

def register_instances(tg_name: str,
                      configuration: Configuration = None,
                      secrets: Secrets = None) -> AWSResponse:
    d2 = json.load(open('exp_data1.txt'))
    """Registers all instances in exp_data1.txt"""
    client = aws_client('elbv2', configuration, secrets)
    tg_arn = get_target_group_arns(tg_names=[tg_name], client=client)
    tg_health = get_targets_health_description(tg_arns=tg_arn, client=client)
    instances = list(map(lambda instance: instance['Id'],d2['target_group']['instances']))

    logger.debug("Registering target {} from target group {}".format(
        instances, tg_name))

    try:
        return client.register_targets(
            TargetGroupArn=tg_arn[tg_name],
            Targets=d2['target_group']['instances']
        )
    except ClientError as e:
        raise FailedActivity('Exception detaching %s: %s' % (
            tg_name, e.response['Error']['Message']))


def set_security_groups(load_balancer_names: List[str],
                        security_group_ids: List[str],
                        configuration: Configuration = None,
                        secrets: Secrets = None) -> List[AWSResponse]:
    """
    Changes the security groups for the specified load balancer(s).
    This action will replace the existing security groups on an application
    load balancer with the specified security groups.

    Parameters:
        - load_balancer_names: a list of load balancer names
        - security_group_ids: a list of security group ids

    returns:
        [
            {
                'LoadBalancerArn': 'string',
                'SecurityGroupIds': ['sg-0000000', 'sg-0000001']
            },
            ...
        ]
    """
    security_group_ids = get_security_groups(
        security_group_ids, aws_client('ec2', configuration, secrets))

    client = aws_client('elbv2', configuration, secrets)
    load_balancers = get_load_balancer_arns(load_balancer_names, client)

    if load_balancers.get('network', []):
        raise FailedActivity(
            'Cannot change security groups of network load balancers.')

    results = []
    for l in load_balancers['application']:
        response = client.set_security_groups(
            LoadBalancerArn=l, SecurityGroups=security_group_ids)

        # add load balancer arn to response
        response['LoadBalancerArn'] = l
        results.append(response)
    return results


def set_subnets(load_balancer_names: List[str],
                subnet_ids: List[str],
                configuration: Configuration = None,
                secrets: Secrets = None) -> List[AWSResponse]:
    """
    Changes the subnets for the specified application load balancer(s)
    This action will replace the existing security groups on an application
    load balancer with the specified security groups.

    Parameters:
        - load_balancer_names: a list of load balancer names
        - subnet_ids: a list of subnet ids

    returns:
        [
            {
                'LoadBalancerArn': 'string',
                'AvailabilityZones': {
                    'ZoneName': 'string',
                    'SubnetId': 'string',
                    'LoadBalancerAddresses': [
                        {
                            'IpAddress': 'string',
                            'AllocationId': 'string'
                        }
                    ]
                }
            },
            ...
        ]
    """
    subnet_ids = get_subnets(
        subnet_ids, aws_client('ec2', configuration, secrets))

    client = aws_client('elbv2', configuration, secrets)
    load_balancers = get_load_balancer_arns(load_balancer_names, client)

    if load_balancers.get('network', []):
        raise FailedActivity(
            'Cannot change subnets of network load balancers.')

    results = []
    for l in load_balancers['application']:
        response = client.set_subnets(
            LoadBalancerArn=l, Subnets=subnet_ids)
        response['LoadBalancerArn'] = l
        results.append(response)
    return results


def delete_load_balancer(load_balancer_names: List[str],
                         configuration: Configuration = None,
                         secrets: Secrets = None):
    """
    Deletes the provided load balancer(s).

    Parameters:
        - load_balancer_names: a list of load balancer names
    """
    client = aws_client('elbv2', configuration, secrets)
    load_balancers = get_load_balancer_arns(load_balancer_names, client)

    for k, v in load_balancers.items():
        if k not in ('application', 'network'):
            continue

        for l in v:
            logger.debug('Deleting load balancer %s' % l)
            client.delete_load_balancer(LoadBalancerArn=l)


###############################################################################
# Private functions
###############################################################################
def get_load_balancer_arns(load_balancer_names: List[str],
                           client: boto3.client) -> Dict[str, List[str]]:
    """
    Returns load balancer arns categorized by the type of load balancer

    return structure:
    {
        'network': ['load balancer arn'],
        'application': ['load balancer arn']
    }
    """
    results = {}
    logger.debug('Searching for load balancer name(s): {}.'.format(
        load_balancer_names))

    try:
        response = client.describe_load_balancers(
            Names=load_balancer_names)

        for lb in response['LoadBalancers']:
            if lb['State']['Code'] != 'active':
                raise FailedActivity(
                    'Invalid state for load balancer {}: '
                    '{} is not active'.format(
                        lb['LoadBalancerName'], lb['State']['Code']))
            results.setdefault(lb['Type'], []).append(
                lb['LoadBalancerArn'])
            results.setdefault('Names', []).append(lb['LoadBalancerName'])
    except ClientError as e:
        raise FailedActivity(e.response['Error']['Message'])

    missing_lbs = [l for l in load_balancer_names if l not in results['Names']]
    if missing_lbs:
        raise FailedActivity(
            'Unable to locate load balancer(s): {}'.format(missing_lbs))

    if not results:
        raise FailedActivity(
            'Unable to find any load balancer(s) matching name(s): {}'.format(
                load_balancer_names))

    return results


def get_target_group_arns(tg_names: List[str],
                          client: boto3.client) -> Dict:
    """
    Return list of target group ARNs based on list of target group names

    return structure:
    {
        "TargetGroupName": "TargetGroupArn",
        ....
    }
    """
    logger.debug("Target group name(s): {} Looking for ARN"
                 .format(str(tg_names)))
    res = client.describe_target_groups(Names=tg_names)
    tg_arns = {}

    for tg in res['TargetGroups']:
        tg_arns[tg['TargetGroupName']] = tg['TargetGroupArn']
    logger.debug("Target groups ARN: {}".format(str(tg_arns)))

    return tg_arns


def get_targets_health_description(tg_arns: Dict,
                                   client: boto3.client) -> Dict:
    """
    Return TargetHealthDescriptions by targetgroups
    Structure:
    {
        "TargetGroupName": {
            "TargetGroupArn": value,
            "TargetHealthDescriptions": TargetHealthDescriptions[]
        },
        ....
    }
    """
    logger.debug("Target group ARN: {} Getting health descriptions"
                 .format(str(tg_arns)))
    tg_health_descr = {}

    for tg in tg_arns:
        tg_health_descr[tg] = {}
        tg_health_descr[tg]['TargetGroupArn'] = tg_arns[tg]
        tg_health_descr[tg]['TargetHealthDescriptions'] = \
            client.describe_target_health(TargetGroupArn=tg_arns[tg])[
            'TargetHealthDescriptions']
    logger.debug("Health descriptions for target group(s) are: {}"
                 .format(str(tg_health_descr)))
    return tg_health_descr


def get_security_groups(sg_ids: List[str], client: boto3.client) -> List[str]:
    try:
        response = client.describe_security_groups(
            GroupIds=sg_ids)['SecurityGroups']
        results = [r['GroupId'] for r in response]
    except ClientError as e:
        raise FailedActivity(e.response['Error']['Message'])

    missing_sgs = [s for s in sg_ids if s not in results]
    if missing_sgs:
        raise FailedActivity('Invalid security group id(s): {}'.format(
            missing_sgs))
    return results


def get_subnets(subnet_ids: List[str], client: boto3.client) -> List[str]:
    try:
        response = client.describe_subnets(SubnetIds=subnet_ids)['Subnets']
        results = [r['SubnetId'] for r in response]
    except ClientError as e:
        raise FailedActivity(e.response['Error']['Message'])

    missing_subnets = [s for s in subnet_ids if s not in results]
    if missing_subnets:
        raise FailedActivity('Invalid subnet id(s): {}'.format(
            missing_subnets))
    return results
