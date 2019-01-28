# encoding: utf-8
from __future__ import unicode_literals

from mainsite.tests import BadgrTestCase


class ManifestFiletests(BadgrTestCase):
    def test_can_retrieve_manifest_file(self):
        response = self.client.get('/.well-known/badgeconnect.json', headers={'Accept': 'application/json'})
        data = response.data
        self.assertEqual(data['@context'], 'https://w3id.org/openbadges/badgeconnect.json')

    def test_manifest_file_is_theme_appropriate(self):
        pass