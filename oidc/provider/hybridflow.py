# -*- coding: utf-8 -*-

from py3oauth2.provider import message

from ..idtoken import IDToken as BaseIDToken
from .authorizationcodeflow import (
    AuthenticationRequest as BaseAuthenticationRequest,
)
from .implicitflow import (
    Response as BaseAuthenticationResponse,
)


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
    nonce = message.Parameter(str, required=True)
    at_hash = message.Parameter(str, required=is_at_hash_required)
    c_hash = message.Parameter(str, required=is_chash_required)


class AuthenticationResponse(BaseAuthenticationResponse):
    __id_token_class__ = IDToken

    # OAuth2.0 parameters
    access_token = message.Parameter(str, required=is_access_token_required)
    token_type = message.Parameter(str, required=is_access_token_required)
    code = message.Parameter(str, required=True)

    id_token = message.Parameter(IDToken, required=is_id_token_required)


class AuthenticationRequest(BaseAuthenticationRequest):
    response = AuthenticationResponse

    # OAuth2.0 parameters
    response_type = message.Parameter(str, required=True)

    def answer(self, provider, owner):
        try:
            try:
                client = provider.store.get_client(self.client_id)
                if client is None or not provider.authorize_client(client):
                    raise message.UnauthorizedClient()

                code = provider.persist_authorization_code(
                    client, owner,
                    provider.generate_authorization_code(), self.scope
                )
                response = self.response.from_dict(self, {
                    'state': self.state,
                    'code': code.get_code(),
                })

                response_types = set(self.response_type.cplit())
                if 'token' in response_types:
                    token = provider.store.persist_access_token(
                        client, owner, provider.generate_access_token(),
                        self.scope, None
                    )
                    response.access_token = token.get_token()
                    response.token_type = token.get_type()
                    response.scope = token.get_scope()
                    response.expires_in = token.get_expires_in()

                if 'id_token' in response_types:
                    response.id_token = self.response.__id_token_class__.issue(
                        provider, client, owner
                    )
                    response.id_token.nonce = self.nonce
                    response.id_token.validate()
            except message.RequestError:
                raise
            except:
                raise message.ServerError()
        except message.ServerError() as why:
            resp = self.err_response(self)
            resp.error = why.kind
            resp.state = self.state
            return resp
        else:
            return response
