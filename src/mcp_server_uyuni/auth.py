from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl


class AuthProvider(RemoteAuthProvider):
    def __init__(self, auth_server):
        verifier = JWTVerifier(
            jwks_uri=auth_server + "/protocol/openid-connect/certs",
            issuer=auth_server,
            audience="mcp-server-uyuni",
            required_scopes=[],
        )

        super().__init__(
            token_verifier=verifier,
            authorization_servers=[AnyHttpUrl(auth_server)],
            base_url="http://localhost:8000", #TODO: Get URL dynamically?
        )
