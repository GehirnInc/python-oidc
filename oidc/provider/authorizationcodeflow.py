# -*- coding: utf-8 -*-

from py3oauth2.provider.authorizationcodegrant import (
    AuthorizationRequest,
    AuthorizationResponse,
)
from py3oauth2.provider.message import Parameter

from ..idtoken import IDToken as BaseIDToken

__all__ = ['IDToken', 'AuthenticationResponse', 'AuthenticationRequest']


class IDToken(BaseIDToken):
    at_hash = Parameter(str)


class AuthenticationResponse(AuthorizationResponse):
    __id_token_class__ = IDToken

    id_token = Parameter(str, required=True)


class AuthenticationRequest(AuthorizationRequest):
    response = AuthenticationResponse

    # OAuth2.0 parameters
    redirect_uri = Parameter(str, required=True)
    response_mode = Parameter(str)

    # OpenID Connect parameters
    nonce = Parameter(str, recommended=True)
    display = Parameter(str)
    prompt = Parameter(str)
    max_age = Parameter(int)
    ui_locales = Parameter(str)
    id_token_hint = Parameter(str)
    login_hint = Parameter(str)
    acr_values = Parameter(str)

    def answer(self, provider, owner):
        resp = super(self.__class__, self).answer(provider, owner)
        if isinstance(resp, self.err_response):
            return resp

        resp.id_token = IDToken()  # here
        return resp
