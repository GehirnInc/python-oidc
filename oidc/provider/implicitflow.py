# -*- coding: utf-8 -*-

from py3oauth2.provider.implicitgrant import (
    Response as BaseResponse,
)
from py3oauth2.provider import message

from ..idtoken import IDToken as BaseIDToken
from .authorizationcodeflow import (
    AuthenticationRequest as BaseRequest,
)

__all__ = ['IDToken', 'Request', 'Response']


def is_access_token_required(resp):
    return resp.request.response_type != 'id_token'


class IDToken(BaseIDToken):
    nonce = message.Parameter(str, required=True)
    at_hash = message.Parameter(str)


class Response(BaseResponse):
    __id_token_class__ = IDToken

    # OAuth2 parameters
    access_token = message.Parameter(str, required=is_access_token_required)
    token_type = message.Parameter(str, required=is_access_token_required)

    # OpenID Connect parameters
    id_token = message.Parameter(__id_token_class__, required=True)


class Request(BaseRequest):
    response = Response

    nonce = message.Parameter(str, required=True)

    def answer(self, provider, owner):
        client = provider.store.get_client(self.client_id)
        if client is None or not provider.authorize_client(client):
            raise message.UnauthorizedClient()

        redirect_uri = self.redirect_uri or client.redirect_uri
        if not redirect_uri:
            raise message.InvalidRequest()
        elif not provider.validate_redirect_uri(redirect_uri):
            raise message.UnauthorizedClient()

        response = self.response(self)
        response.state = self.state

        id_token = self.response.__id_token_class__.issue(
            provider, owner, client)
        id_token.nonce = self.nonce
        id_token.validate()
        response.id_token = id_token

        if self.response_type != 'id_token':
            token = provider.store.persist_access_token(
                client, owner, provider.generate_access_token(),
                self.scope, None
            )
            response.access_token = token.get_token()
            response.token_type = token.get_type()
            response.scope = token.get_scope()
            response.expires_in = token.get_expires_in()

        return response
