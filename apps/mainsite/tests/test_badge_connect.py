# encoding: utf-8
from __future__ import unicode_literals

from Crypto.PublicKey import RSA
import datetime
import jwcrypto.jwk as jwk
import python_jwt as jwt
import requests
import responses
import time
from urllib import quote
import urlparse

from django.conf import settings
from django.shortcuts import reverse

from mainsite.badge_connect_api import badge_connect_api_info
from mainsite.models import BadgrApp
from mainsite.tests import BadgrTestCase


class ManifestFileTests(BadgrTestCase):
    def test_can_retrieve_manifest_files(self):
        ba = BadgrApp.objects.create(name='test', cors='some.domain.com')
        response = self.client.get('/bc/v1/manifest/some.domain.com', headers={'Accept': 'application/json'})
        self.assertEqual(response.status_code, 200)
        data = response.data
        self.assertEqual(data['@context'], 'https://w3id.org/openbadges/badgeconnect/v1')
        self.assertIn('https://purl.imsglobal.org/spec/obc/v1p0/oauth2scope/assertion.readonly', data['badgeConnectAPI'][0]['scopesOffered'])

        response = self.client.get('/bc/v1/manifest/some.otherdomain.com', headers={'Accept': 'application/json'})
        self.assertEqual(response.status_code, 404)

        response = self.client.get('/.well-known/badgeconnect.json')
        self.assertEqual(response.status_code, 302)

        url = urlparse.urlparse(response._headers['location'][1])
        self.assertIn('/bc/v1/manifest/', url.path)

    def test_manifest_file_is_theme_appropriate(self):
        ba = BadgrApp.objects.create(name='test', cors='some.domain.com')
        response = self.client.get('/bc/v1/manifest/some.domain.com', headers={'Accept': 'application/json'})
        data = response.data
        self.assertEqual(data['badgeConnectAPI'][0]['name'], ba.name)


class BadgeConnectAuthorizationTests(BadgrTestCase):
    @responses.activate
    def test_can_retrieve_authorization_endpoint(self):
        ba = BadgrApp.objects.create(name='test', cors='some.domain.com')
        info = badge_connect_api_info(ba.cors)
        user = self.setup_user(authenticate=True)

        # Set up relying party
        redirect_uri = 'http://exampleissuer.com/redirect'
        requested_scopes = [
            "https://purl.imsglobal.org/spec/obc/v1p0/oauth2scope/assertion.create",
            "https://purl.imsglobal.org/spec/obc/v1p0/oauth2scope/profile.readonly"
        ]
        client_id = 'BADGE_CONNECT'

        manifest_data = {
            'id': 'http://exampleissuer.com/.well-known/badgeconnect.json',
            '@context': 'https://w3id.org/openbadges/badgeconnect/v1',
            'badgeConnectAPI': [
                {
                    'name': 'Test Issuing System',
                    'apiBase': 'http://exampleissuer.com/v1',
                    'privacyPolicyUrl': 'http://exampleissuer.com/privacy',
                    'termsOfServiceUrl': 'http://exampleissuer.com/terms',
                    'scopesRequested': requested_scopes,
                    'redirectUris': [redirect_uri],
                    'version': 1
                }
            ]
        }
        responses.add(responses.GET, manifest_data['id'], json=manifest_data)
        response = requests.get(manifest_data['id'])

        # Get application info
        url = '/o/authorize?response_type=code&approval_prompt=auto&client_id={}&redirect_uri={}&scope={}'.format(
            client_id, quote(redirect_uri), quote(' '.join(requested_scopes))
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(set(response.data['scopes']), set(requested_scopes))

        # Submit user approval and obtain redirect/code
        url = '/o/authorize'
        data = {
            "allow": True,
            "response_type": "code",
            "client_id": response.data['client_id'],
            "redirect_uri": redirect_uri,
            "scopes": requested_scopes,
            "state": ""
        }
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['success_url'].startswith(redirect_uri))
        url = urlparse.urlparse(response.data['success_url'])
        code = urlparse.parse_qs(url.query)['code'][0]

        # Obtain access_token from code
        self.client.logout()  # this next request should not be related to the user
        # private_key = RSA.generate(2048)
        # client_key_data = {
        #     "keys": [
        #         {
        #             "alg": "RS256",
        #             "kty": "RSA",
        #             "use": "sig",
        #             "x5c": ["MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDFdw/djSAge/EtnXgupmeuSEIU28Y2uIuGLMtGVCA3GoqtpY7CjLBzS6/wQ1lZ/hDJ5bIqp98Rep65f1Jz4CVKl7ql/4+Ls8SrvnDLmLEQ5RqfgXULo96lA5Dr8KMMbWj+4w35aU0st4xX+e0WKj+1qeGxqZttEV8+TtSPdWaOBQIDAQAB"],
        #             "n": "xXcP3Y0gIHvxLZ14LqZnrkhCFNvGNriLhizLRlQgNxqKraWOwoywc0uv8ENZWf4QyeWyKqffEXqeuX9Sc-AlSpe6pf-Pi7PEq75wy5ixEOUan4F1C6PepQOQ6_CjDG1o_uMN-WlNLLeMV_ntFio_tanhsambbRFfPk7Uj3VmjgU",
        #             "e":"AQAB",
        #             "kid":"NjgyZWUxODcwOTc4M2M1Y2Q3NzQ1MDhiOTI4MWRhMTM1ZGRmMDIwZQ",
        #             "x5t": "NjgyZWUxODcwOTc4M2M1Y2Q3NzQ1MDhiOTI4MWRhMTM1ZGRmMDIwZQ"
        #         }
        #     ]
        # }

        key = jwk.JWK.generate(kty='RSA', size=2048)
        priv_pem = key.export_to_pem(private_key=True, password=None)
        pub_pem = key.export_to_pem()
        priv_key = jwk.JWK.from_pem(priv_pem)
        pub_key = jwk.JWK.from_pem(pub_pem)

        responses.add(
            responses.GET, "http://{}/.well-known/jwks.json".format(url.netloc),
            body=key.export(),
            content_type='application/json'
        )

        payload = {
            "iss": url.netloc,
            "sub": "BADGE_CONNECT",
            "aud": settings.HTTP_ORIGIN + "/o/token"
        }

        token = jwt.generate_jwt(payload, priv_key, 'RS256', datetime.timedelta(minutes=60))
        # header, claims = jwt.verify_jwt(token, pub_key, ['RS256'])

        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': 'BADGE_CONNECT',
            'redirect_uri': redirect_uri,
            'scope': ' '.join(requested_scopes),
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': token
        }

        response = self.client.post('/o/token', data=data)
        self.assertEqual(response.status_code, 200)
