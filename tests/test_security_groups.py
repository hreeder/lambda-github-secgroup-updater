"""
    Core tests for working with AWS EC2 Security Groups
"""
import unittest

import responses

from botocore.stub import Stubber

from secgrp_updater import main

class TestSecurityGroups(unittest.TestCase):
    """ Security Group Tests """

    # pylint: disable=too-many-instance-attributes
    # Attributes are here as re-usable content,
    # Happy with how many there are

    def setUp(self):
        """ setUp runs before any tests """
        self.stubber = Stubber(main.EC2)

        self.default_managed_group_name = 'AllowGitHubWebhooks'

        self.unmanaged_id = "123abc"
        self.managed_id = "abc123"
        self.managed_id_2 = "def456"

        self.unmanaged_sg = {
            "GroupId": f'sg-{self.unmanaged_id}',
            "VpcId": f'vpc-{self.unmanaged_id}'
        }
        self.managed_sg = {
            "GroupId": f'sg-{self.managed_id}',
            "VpcId": f'vpc-{self.managed_id}',
            "IpPermissionsEgress": [],
            "IpPermissions": []
        }
        self.managed_sg_2 = {
            "GroupId": f'sg-{self.managed_id_2}',
            "VpcId": f'vpc-{self.managed_id_2}',
            "IpPermissionsEgress": [],
            "IpPermissions": []
        }

        self.allowed_ranges = ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24']

    def test_get_sec_groups_with_default_name(self):
        """ Tests that security groups with the default name are retrieved successfully """
        mock_response = {"SecurityGroups": [self.managed_sg]}
        expected_params = {'GroupNames': [self.default_managed_group_name]}
        self.stubber.add_response('describe_security_groups', mock_response, expected_params)

        with self.stubber:
            result = main.get_or_create_secgroups(
                [f'vpc-{self.managed_id}'],
                self.default_managed_group_name
            )

            self.assertIn(f'sg-{self.managed_id}', [group['GroupId'] for group in result])
            self.stubber.assert_no_pending_responses()

    def test_get_sec_groups_does_not_manage_undefined_vpcs(self):
        """
            Tests that VPCs not specified with security groups of
            the correct name are not managed
        """
        mock_response = {"SecurityGroups": [self.managed_sg, self.unmanaged_sg]}
        expected_params = {'GroupNames': [self.default_managed_group_name]}
        self.stubber.add_response(
            'describe_security_groups',
            mock_response,
            expected_params
        )

        with self.stubber:
            result = main.get_or_create_secgroups(
                [f'vpc-{self.managed_id}'],
                self.default_managed_group_name
            )

            self.assertNotIn(f'sg-{self.unmanaged_id}', [group['GroupId'] for group in result])
            self.stubber.assert_no_pending_responses()

    def test_get_sec_groups_creates_group(self):
        """ Tests security group is created when required """
        expected_describe_params = {'GroupNames': [self.default_managed_group_name]}
        self.stubber.add_client_error(
            'describe_security_groups',
            service_error_code='InvalidGroup.NotFound',
            expected_params=expected_describe_params
        )

        mock_create_response = {
            'GroupId': f'sg-{self.managed_id}'
        }
        expected_create_params = {
            'Description': 'Allow GitHub Webhooks [Managed by GitHub-SecGrp-Updater Lambda]',
            'GroupName': self.default_managed_group_name,
            'VpcId': f'vpc-{self.managed_id}'
        }
        self.stubber.add_response(
            'create_security_group',
            mock_create_response,
            expected_create_params
        )

        with self.stubber:
            result = main.get_or_create_secgroups(
                [f'vpc-{self.managed_id}'],
                self.default_managed_group_name
            )

            self.assertIn(f'sg-{self.managed_id}', [group['GroupId'] for group in result])
            self.stubber.assert_no_pending_responses()

    def test_get_sec_groups_creates_group_multiple(self):
        """
            Consider when getting security groups and some are found but not others
            And test that ones not found are created
        """
        mock_describe_response = {'SecurityGroups': [self.managed_sg]}
        expected_describe_params = {'GroupNames': [self.default_managed_group_name]}
        self.stubber.add_response(
            'describe_security_groups',
            mock_describe_response,
            expected_describe_params
        )

        mock_create_response = {'GroupId': f'sg-{self.managed_id_2}'}
        expected_create_params = {
            'Description': 'Allow GitHub Webhooks [Managed by GitHub-SecGrp-Updater Lambda]',
            'GroupName': self.default_managed_group_name,
            'VpcId': f'vpc-{self.managed_id_2}'
        }
        self.stubber.add_response(
            'create_security_group',
            mock_create_response,
            expected_create_params
        )

        with self.stubber:
            vpcs = [
                f'vpc-{self.managed_id}',
                f'vpc-{self.managed_id_2}'
            ]
            result = main.get_or_create_secgroups(vpcs, self.default_managed_group_name)
            self.assertEqual(len(vpcs), len(result))

            self.stubber.assert_no_pending_responses()

    def test_unknown_boto3_errors_cause_no_processing(self):
        """
            We should return an empty list if there's an unknown error
            from boto3 / AWS API
        """
        self.stubber.add_client_error(
            'describe_security_groups',
            service_error_code='FooBar.Error'
        )

        with self.stubber:
            result = main.get_or_create_secgroups(
                [f'vpc-{self.managed_id}'],
                self.default_managed_group_name
            )

            self.assertEqual(0, len(result))
            self.stubber.assert_no_pending_responses()

    # @responses.activate
    # def test_update_sec_groups(self):
    #     """
    #         Test the actual run function to know if security groups have been updated
    #     """
    #     responses.add(
    #         responses.GET,
    #         'https://api.github.com/meta',
    #         json={'hooks': self.allowed_ranges}
    #     )

    #     mock_describe_response = {
    #         'SecurityGroups': [self.managed_sg, self.managed_sg_2]
    #     }
    #     expected_describe_params = {'GroupNames': [self.default_managed_group_name]}
    #     self.stubber.add_response(
    #         'describe_security_groups',
    #         mock_describe_response,
    #         expected_describe_params
    #     )

    #     expected_update_params_1 = {
    #         'GroupId': f'sg-{self.managed_id}',
    #         'IpPermissions': [
    #             {
    #                 'FromPort': 443,
    #                 'ToPort': 443,
    #                 'IpProtocol': 'tcp',
    #                 'IpRanges': [{'CidrIp': ip_range} for ip_range in self.allowed_ranges]
    #             }
    #         ]
    #     }
    #     expected_update_params_2 = {
    #         'GroupId': f'sg-{self.managed_id_2}',
    #         'IpPermissions': [
    #             {
    #                 'FromPort': 443,
    #                 'ToPort': 443,
    #                 'IpProtocol': 'tcp',
    #                 'IpRanges': [{'CidrIp': ip_range} for ip_range in self.allowed_ranges]
    #             }
    #         ]
    #     }

    #     self.stubber.add_response(
    #         'update_security_group_rule_descriptions_ingress',
    #         {},
    #         expected_update_params_1
    #     )
    #     self.stubber.add_response(
    #         'update_security_group_rule_descriptions_ingress',
    #         {},
    #         expected_update_params_2
    #     )

    #     with self.stubber:
    #         main.run([f'vpc-{self.managed_id}', f'vpc-{self.managed_id_2}'])

    #         self.stubber.assert_no_pending_responses()

    def test_update_security_group_adds_rules(self):
        """ Test update_security_group adds correct rules """
        self.stubber.add_response(
            'authorize_security_group_ingress',
            {},
            {
                "GroupId": f'sg-{self.managed_id}',
                "IpPermissions": [{
                    "FromPort": port,
                    "ToPort": port,
                    "IpProtocol": "tcp",
                    "IpRanges": [{
                        "Description": "GitHub",
                        "CidrIp": ip_range
                    } for ip_range in self.allowed_ranges]
                } for port in [80, 443]]
            }
        )

        with self.stubber:
            main.update_security_group(self.managed_sg, self.allowed_ranges)

            self.stubber.assert_no_pending_responses()

    def test_update_security_group_adds_partial_rules(self):
        """ Test update_security_group only adds relevant rules """
        self.stubber.add_response(
            'authorize_security_group_ingress',
            {},
            {
                "GroupId": f'sg-{self.managed_id}',
                "IpPermissions": [{
                    "FromPort": port,
                    "ToPort": port,
                    "IpProtocol": "tcp",
                    "IpRanges": [{
                        "Description": "GitHub",
                        "CidrIp": ip_range
                    } for ip_range in self.allowed_ranges[1:]]
                } for port in [80, 443]]
            }
        )

        with self.stubber:
            main.update_security_group({
                "GroupId": f'sg-{self.managed_id}',
                "VpcId": f'vpc-{self.managed_id}',
                "IpPermissionsEgress": [],
                "IpPermissions": [{
                    "FromPort": port,
                    "ToPort": port,
                    "IpRanges": [{
                        "Description": "GitHub",
                        "CidrIp": self.allowed_ranges[0]
                    }]
                } for port in [80, 443]]
            }, self.allowed_ranges)

            self.stubber.assert_no_pending_responses()

    def test_update_security_group_removes_ingress_rules(self):
        """ Test update_security_group removes any rules NOT in the allowed list """
        ranges = [item for item in self.allowed_ranges] # This MUST be a copy, not a reference
        ranges.append("10.0.0.0/8")

        self.stubber.add_response(
            'revoke_security_group_ingress',
            {},
            {
                "GroupId": f'sg-{self.managed_id}',
                "IpPermissions": [{
                    "FromPort": port,
                    "ToPort": port,
                    "IpProtocol": "tcp",
                    "IpRanges": [{
                        "Description": "GitHub",
                        "CidrIp": "10.0.0.0/8"
                    }]
                } for port in [80, 443]]
            }
        )

        with self.stubber:
            main.update_security_group({
                "GroupId": f'sg-{self.managed_id}',
                "VpcId": f'vpc-{self.managed_id}',
                "IpPermissionsEgress": [],
                "IpPermissions": [{
                    "FromPort": port,
                    "ToPort": port,
                    "IpRanges": [{
                        "Description": "GitHub",
                        "CidrIp": ip_range
                    } for ip_range in ranges]
                } for port in [80, 443]]
            }, self.allowed_ranges)

            self.stubber.assert_no_pending_responses()

    def test_update_security_group_removes_egress_rules(self):
        """ Test update_security_group removes ALL egress rules """
        self.stubber.add_response(
            'revoke_security_group_egress',
            {},
            {
                "GroupId": f'sg-{self.managed_id}',
                "IpPermissions": [{
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpProtocol": "tcp",
                    "IpRanges": [{
                        "Description": "TestNet",
                        "CidrIp": "0.0.0.0/0"
                    }]
                }]
            }
        )

        with self.stubber:
            main.update_security_group({
                "GroupId": f'sg-{self.managed_id}',
                "VpcId": f'vpc-{self.managed_id}',
                "IpPermissionsEgress": [{
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpProtocol": "tcp",
                    "IpRanges": [{
                        "Description": "TestNet",
                        "CidrIp": "0.0.0.0/0"
                    }]
                }],
                "IpPermissions": []
            }, [])

        self.stubber.assert_no_pending_responses()
