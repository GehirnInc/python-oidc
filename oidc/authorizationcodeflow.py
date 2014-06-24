# -*- coding: utf-8 -*-

from py3oauth2 import message
from py3oauth2.authorizationcodegrant import (
    AccessTokenRequest,
    AuthorizationRequest,
)

from oidc.idtoken import IDToken as BaseIDToken

__all__ = ['IDToken', 'AuthenticationRequest', 'AccessTokenRequest']


class AuthenticationRequest(AuthorizationRequest):
    # OAuth2.0 parameters
    response_type = message.Parameter(str, required=True)
    scope = message.Parameter(str, required=True)
    redirect_uri = message.Parameter(str, required=True)

    # OAuth2.0 Multiple Response Type Encoding Practices
    response_mode = message.Parameter(str)

    # OpenID Connect parameters
    nonce = message.Parameter(str, recommended=True)
    display = message.Parameter(str)
    prompt = message.Parameter(str)
    max_age = message.Parameter(int)
    ui_locales = message.Parameter(str)
    id_token_hint = message.Parameter(str)
    login_hint = message.Parameter(str)
    acr_values = message.Parameter(str)


class AccessTokenResponse(message.AccessTokenResponse):
    id_token = message.Parameter(str, required=True)


class IDToken(BaseIDToken):
    at_hash = message.Parameter(str)


class AccessTokenRequest(AccessTokenRequest):
    response = AccessTokenResponse
    id_token = IDToken

    def answer(self, provider, owner):
        response = super(AccessTokenRequest, self).answer(provider, owner)

        client = provider.store.get_client(self.client_id)
        access_token = provider.store.get_access_token(response.access_token)
        id_token = self.id_token(response,
                                 provider.get_iss(),
                                 access_token.get_owner().get_sub(),
                                 client.get_id(),
                                 provider.get_id_token_lifetime())
        id_token.at_hash = provider.left_hash(client.get_jws_alg(),
                                              response.access_token)
        response.id_token =\
            provider.encode_token(id_token, client, response.access_token)

        return response
