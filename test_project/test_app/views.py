from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from keypair_permissions.permissions import HasHttpCrypoAuthorization


class AuthTestApiView(GenericAPIView):
    """Test Crypto Auth Mixin."""

    permission_classes = [HasHttpCrypoAuthorization]

    def get(self, request):
        """GET method."""
        return Response(request.body)

    def post(self, request):
        """POST method."""
        return Response(request.data)
