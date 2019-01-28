from rest_framework.views import APIView


class BadgeConnectManifestView(APIView):
    def get(self, **kwargs):
        return {}