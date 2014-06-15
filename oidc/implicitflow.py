# -*- coding: utf-8 -*-

from py3oauth2.implicitgrant import Response
from py3oauth2.message import Parameter

from oidc.authorizationcodeflow import AuthenticationRequest
from oidc.errors import (
    ErrorException,
    UnauthorizedClient,
)
from oidc.idtoken import IDToken
from oidc.interfaces import IClient

__all__ = ['IDToken', 'Request', 'Response']


def is_access_token_required(resp):
    return resp.request.response_type != 'id_token'


class IDToken(IDToken):
    nonce = Parameter(str, required=True)
    at_hash = Parameter(str)


class Response(Response):

    # OAuth2 parameters
    access_token = Parameter(str, required=is_access_token_required)
    token_type = Parameter(str, required=is_access_token_required)

    # OpenID Connect parameters
    id_token = Parameter(str, required=True)


class Request(AuthenticationRequest):
    response = Response
    id_token = IDToken

    nonce = Parameter(str, required=True)

    def answer(self, provider, owner):
        client = provider.store.get_client(self.client_id)
        if not isinstance(client, IClient):
            raise UnauthorizedClient(self, self.redirect_uri)

        if not provider.validate_redirect_uri(client, self.redirect_uri):
            raise UnauthorizedClient(self, self.redirect_uri)

        response = self.response(self, self.redirect_uri)

        id_token = self.id_token(response,
                                 provider.get_iss(),
                                 owner.get_sub(),
                                 client.get_id(),
                                 provider.get_id_token_lifetime())
        id_token.nonce = self.nonce

        if self.response_type != 'id_token':  # `id_token token`
            try:
                scope = provider.normalize_scope(self.scope)
                token = provider.store.issue_access_token(client, owner, scope)
            except ErrorException as why:
                why.request = self
                why.redirect_uri = self.redirect_uri
                raise
            else:
                response.update({
                    'access_token': token.get_token(),
                    'token_type': token.get_type(),
                    'scope': ' '.join(token.get_scope()),
                    'expires_in':  token.get_expires_in(),
                })

                id_token.at_hash = provider.left_hash(client.get_jws_alg(),
                                                      token.get_token())

        response.update({
            'state': self.state,
            'id_token': provider.encode_token(id_token, client),
        })

        return response
