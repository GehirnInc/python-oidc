# -*- coding: utf-8 -*-

from py3oauth2.provider.message import (
    Parameter,
    RequestError,
    ServerError,
)

from ..idtoken import IDToken as BaseIDToken
from .authorizationcodeflow import (
    AuthenticationRequest as BaseAuthenticationRequest,
)
from .implicitflow import Response as BaseAuthenticationResponse


def is_at_hash_required(idtoken):
    # TODO: implement this
    return False


def is_chash_required(idtoken):
    # TODO: implement this
    return False


def is_access_token_required(resp):
    types = set(resp.request.response_type.split())
    return 'token' in types


def is_id_token_required(resp):
    types = set(resp.request.response_type.split())
    return 'id_token' in types


class IDToken(BaseIDToken):
    nonce = Parameter(str, required=True)
    at_hash = Parameter(str, required=is_at_hash_required)
    c_hash = Parameter(str, required=is_chash_required)


class AuthenticationResponse(BaseAuthenticationResponse):
    __id_token_class__ = IDToken

    # OAuth2.0 parameters
    access_token = Parameter(str, required=is_access_token_required)
    token_type = Parameter(str, required=is_access_token_required)
    code = Parameter(str, required=True)

    # OpenID Connect parameters
    id_token = Parameter(__id_token_class__, required=is_id_token_required)


class AuthenticationRequest(BaseAuthenticationRequest):
    response = AuthenticationResponse

    def answer(self, provider, owner):
        try:
            response_types = set(self.response_type.split())
            if 'id_token' in response_types:
                response = super().answer(provider, owner)
                if isinstance(response, self.err_response):
                    return response

                response.id_token.nonce = self.nonce
            else:
                response = super(
                    BaseAuthenticationRequest, self
                ).answer(provider, owner)
                if isinstance(response, self.err_response):
                    return response

            if 'token' in response_types:
                client = provider.store.get_client(self.client_id)
                token = provider.store.persist_access_token(
                    client, owner, provider.generate_access_token(),
                    self.scope, None)
                response.access_token = token.get_token()
                response.token_type = token.get_type()
                response.scope = token.get_scope()
                response.expires_in = token.get_expires_in()

            return response
        except BaseException as why:
            if not isinstance(why, RequestError):
                why = ServerError()

            resp = self.err_response(self)
            resp.error = why.kind
            resp.state = self.state
            return resp
