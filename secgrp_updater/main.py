"""
    secgrp_updater

    This is designed to allow retrieval of GitHub Hook IPs and manage a security group,
    Allowing GitHub Hooks through said group dynamically.
"""
import logging

from typing import List

import boto3
import botocore.exceptions
import requests

LOGGER = logging.getLogger(__name__)
EC2 = boto3.client('ec2')


def _create_secgroup(vpc: str, name: str) -> dict:
    """Creates security group if necessary.

    Args:
        vpc: VPC ID in which to create the Security Group
        name: Security Group Name

    Returns:
        Security Group dict from boto3
    """
    created_group = EC2.create_security_group(
        Description='Allow GitHub Webhooks [Managed by GitHub-SecGrp-Updater Lambda]',
        GroupName=name,
        VpcId=vpc
    )

    return created_group


def get_or_create_secgroups(
        vpc_ids: list,
        security_group_name: str
) -> list:
    """Gets or creates security groups to be managed by this library

    Args:
        vpc_ids: List of VPC IDs to search for managed Security Group
        security_group_name (optional): Override the default naming of the managed security group

    Returns:
        List of security group IDs
    """
    groups = []
    try:
        existing = EC2.describe_security_groups(GroupNames=[security_group_name])
        groups = [
            group for group in existing['SecurityGroups'] if group['VpcId'] in vpc_ids
        ]

        if len(groups) != len(vpc_ids):
            vpcs_with_sec_groups = set(group['VpcId'] for group in groups)
            vpcs_without_sec_group = set(vpc_ids) - vpcs_with_sec_groups

            for vpc_id in vpcs_without_sec_group:
                groups.append(_create_secgroup(vpc_id, security_group_name)['GroupId'])

    except botocore.exceptions.ClientError as ex:
        if ex.response['Error']['Code'] == 'InvalidGroup.NotFound':
            for vpc_id in vpc_ids:
                groups.append(_create_secgroup(vpc_id, security_group_name))
        else:
            LOGGER.error('Unexpected Boto3 Error', exc_info=True)
            return []   # Given this returns a list of Group IDs, returning an empty
                        # list will prevent further code running

    return groups


def get_github_ips() -> List[str]:
    """Gets GitHub's Hooks IP Ranges

    Returns:
        List of IP Ranges
    """
    resp = requests.get(
        'https://api.github.com/meta',
        headers={
            'User-Agent': 'hreeder/security-group-synchronizer'
        }
    )
    data = resp.json()
    return data['hooks']


def update_security_group(
        group: dict,
        ip_ranges: list
) -> None:
    """ Updates an individual security group """
    current_ranges = set()
    for ip_permission in group['IpPermissions']:
        for ip_range in ip_permission['IpRanges']:
            current_ranges.add(ip_range['CidrIp'])

    ranges_to_add = sorted(set(ip_ranges) - current_ranges)
    if ranges_to_add:
        ingresses = [{
            "FromPort": port,
            "ToPort": port,
            "IpProtocol": "tcp",
            "IpRanges": [{
                "Description": "GitHub",
                "CidrIp": ip_range
            } for ip_range in ranges_to_add]
        } for port in [80, 443]]

        EC2.authorize_security_group_ingress(
            GroupId=group['GroupId'],
            IpPermissions=ingresses
        )

    ranges_to_remove = sorted(current_ranges - set(ip_ranges))
    if ranges_to_remove:
        ingresses = [{
            "FromPort": port,
            "ToPort": port,
            "IpProtocol": "tcp",
            "IpRanges": [{
                "Description": "GitHub",
                "CidrIp": ip_range
            } for ip_range in ranges_to_remove]
        } for port in [80, 443]]

        EC2.revoke_security_group_ingress(
            GroupId=group['GroupId'],
            IpPermissions=ingresses
        )

    if group['IpPermissionsEgress']:
        EC2.revoke_security_group_egress(
            GroupId=group['GroupId'],
            IpPermissions=group['IpPermissionsEgress']
        )


def run(
        vpc_ids: list,
        managed_sg_name: str = 'AllowGitHubWebhooks'
) -> None:  # pragma: no cover
    """
        Updates security groups to have current GitHub Ranges Only

        This has "pragma: no cover" set as it just calls other tested methods
        This function should have NO EXTRA logic.
    """
    secgroups = get_or_create_secgroups(vpc_ids, managed_sg_name)
    ip_ranges = get_github_ips()

    for secgroup in secgroups:
        update_security_group(secgroup, ip_ranges)
