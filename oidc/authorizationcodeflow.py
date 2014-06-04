# -*- coding: utf-8 -*-

from py3oauth2 import message
from py3oauth2.authorizationcodegrant import (
    AuthorizationRequest,
    AuthorizationResponse,
)

from oidc.idtoken import IDToken as BaseIDToken

__all__ = ['IDToken', 'AuthenticationResponse', 'AuthenticationRequest']


class IDToken(BaseIDToken):
    at_hash = message.Parameter(str)


class AuthenticationResponse(AuthorizationResponse):
    __id_token_class__ = IDToken

    id_token = message.Parameter(__id_token_class__, required=True)


class AuthenticationRequest(AuthorizationRequest):
    response = AuthenticationResponse

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

    def answer(self, provider, owner):
        resp = super().answer(provider, owner)

        client = provider.store.get_client(self.client_id)
        resp.id_token =\
            self.__id_token_class__.issue(provider, owner, client)
