# -*- coding: utf-8 -*-

from py3oauth2.provider.authorizationcodegrant import (
    AuthorizationRequest,
    AuthorizationResponse,
)
from py3oauth2.provider import message

from ..idtoken import IDToken as BaseIDToken

__all__ = ['IDToken', 'AuthenticationResponse', 'AuthenticationRequest']


class IDToken(BaseIDToken):
    at_hash = message.Parameter(str)


class AuthenticationResponse(AuthorizationResponse):
    __id_token_class__ = IDToken

    id_token = message.Parameter(__id_token_class__, required=True)


class AuthenticationRequest(AuthorizationRequest):
    response = AuthenticationResponse

    # OAuth2.0 parameters
    redirect_uri = message.Parameter(str, required=True)
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
        try:
            try:
                resp = super(self.__class__, self).answer(provider, owner)
                if isinstance(resp, self.err_response):
                    return resp

                client = provider.store.get_client(self.client_id)
                if client is None or not provider.authorize_client(client):
                    raise message.UnauthorizedClient()

                resp.id_token =\
                    self.__id_token_class__.issue(provider, owner, client)
                resp.id_token.validate()
            except message.RequestError as why:
                raise
            except:
                raise message.ServerError()
        except message.RequestError as why:
            resp = self.err_response(self)
            resp.error = why.kind
            resp.state = self.state
            return resp
        else:
            return resp
