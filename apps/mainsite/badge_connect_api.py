from django.conf import settings
from django.shortcuts import reverse
from django.views.generic.base import RedirectView
from oauth2_provider.models import AccessToken, Application
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import BadgrApp, BadgrAppManager
from .serializers import BadgeConnectManifestSerializer


def badge_connect_api_info(domain):
    try:
        badgr_app = BadgrApp.cached.get(cors=domain)
    except BadgrApp.DoesNotExist:
        return None

    return {
        "@context": "https://w3id.org/openbadges/badgeconnect/v1",
        "id": '{}{}'.format(
                settings.HTTP_ORIGIN,
                reverse('badge_connect_manifest', kwargs={'domain': domain})
            ),
        "badgeConnectAPI": [{
            "name": badgr_app.name,
            "image": "https://placekitten.com/300/300",
            "apiBase": '{}{}'.format(settings.HTTP_ORIGIN, '/bc/v1'),
            "version": 1,
            "scopesOffered": [
                "https://purl.imsglobal.org/spec/obc/v1p0/oauth2scope/assertion.readonly",
                "https://purl.imsglobal.org/spec/obc/v1p0/oauth2scope/assertion.create",
                "https://purl.imsglobal.org/spec/obc/v1p0/oauth2scope/profile.readonly"
            ],
            "scopesRequested": [],  # Not implementing relying party yet.
            "authorizationUrl": "{}/auth/oauth2/authorize".format(domain),
            "tokenUrl": "{}{}".format(
                settings.HTTP_ORIGIN,
                reverse('oauth2_provider_token')
            ),
            "redirectUris": [],  # Not implementing relying party yet.
            "termsOfServiceUrl": "https://badgr.com/terms-of-service.html",
            "privacyPolicyUrl": "https://badgr.com/privacy-policy.html",
            "keys": "{}{}".format(
                settings.HTTP_ORIGIN,
                reverse('badge_connect_keyset')
            ),
        }]
    }


class BadgeConnectManifestView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, **kwargs):
        data = badge_connect_api_info(kwargs.get('domain'))
        if data is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = BadgeConnectManifestSerializer(data)
        return Response(serializer.data)


class BadgeConnectManifestRedirectView(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        badgr_app = BadgrApp.objects.get_current(self.request)
        return settings.HTTP_ORIGIN + reverse('badge_connect_manifest', kwargs={'domain': badgr_app.cors})


class BadgeConnectKeysetView(APIView):
    def get(self, domain, **kwargs):
        return {
            'keys': []
        }
