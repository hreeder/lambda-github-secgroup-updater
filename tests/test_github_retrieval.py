"""Check the GitHub IP retrieval function does what's expected"""
import unittest

import responses

from secgrp_updater import main

class TestGithubRetrieval(unittest.TestCase):
    """Check the GitHub IP retrieval function does what's expected"""

    @responses.activate
    def test_get_github_ips(self):
        """Check the GitHub IP retrieval function does what's expected"""
        responses.add(
            responses.GET,
            'https://api.github.com/meta',
            json={'hooks': ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24']}
        )

        hooks = main.get_github_ips()
        self.assertIn('192.0.2.0/24', hooks)
        self.assertIn('198.51.100.0/24', hooks)
        self.assertIn('203.0.113.0/24', hooks)
