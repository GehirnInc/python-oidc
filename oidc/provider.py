# -*- coding: utf-8- -*-

import hashlib

from py3oauth2.provider import (
    AuthorizationProvider,
    ResourceProvider,
)

from oidc import (
    authorizationcodeflow,
    hybridflow,
    implicitflow,
)
from oidc.errors import AccessDenied
from oidc.idtoken import IDToken
from oidc.interfaces import (
    IClient,
    IStore,
)

from jwt.jwk import (
    JWK,
    JWKSet,
)
from jwt.jwt import JWT
from jwt.utils import b64_encode


class AuthorizationProvider(AuthorizationProvider):

    def __init__(self, store, iss, jwkset, is_token_encryption_enabled=False):
        assert isinstance(store, IStore)
        assert isinstance(iss, str)
        assert isinstance(jwkset, JWKSet)
        assert isinstance(is_token_encryption_enabled, bool)
        super(AuthorizationProvider, self).__init__(store)

        self.iss = iss
        self.jwkset = jwkset
        self.is_token_encryption_enabled = is_token_encryption_enabled

        self.add_authorization_handler(
            ('code', ), authorizationcodeflow.AuthenticationRequest)
        self.add_token_handler('authorization_code',
                               authorizationcodeflow.AccessTokenRequest)

        self.add_authorization_handler(
            ('code', 'token'), hybridflow.AuthenticationRequest)
        self.add_authorization_handler(
            ('code', 'id_token'), hybridflow.AuthenticationRequest)
        self.add_authorization_handler(
            ('code', 'id_token', 'token'), hybridflow.AuthenticationRequest)

        self.add_authorization_handler(
            ('id_token', ), implicitflow.Request)
        self.add_authorization_handler(
            ('id_token', 'token'), implicitflow.Request)

    def get_iss(self):
        return self.iss

    def encode_token(self, token, client, access_token=None):
        assert isinstance(token, IDToken)
        assert isinstance(client, IClient)
        assert isinstance(access_token, (str, type(None)))

        jwkset = self.jwkset.copy()
        if access_token:
            jwkset.append(JWK.from_dict({
                'kty': 'oct',
                'k': access_token,
            }))

        jwt = JWT(jwkset)
        jws = jwt.encode(dict(alg=client.get_jws_alg()),
                         token.to_json().encode('utf8'))

        if not self.is_token_encryption_enabled:
            return jws

        jwe = jwt.encode(dict(alg=client.get_jwe_alg(),
                              enc=client.get_jwe_enc(),
                              cty='JWT'),
                         jws)
        return jwe

    def get_id_token_lifetime(self):
        return 300

    def left_hash(self, alg, target):
        if isinstance(target, str):
            target = target.encode('ascii')

        if alg.startswith('RS') or alg.startswith('HS'):
            if alg.endswith('256'):
                hashfunc = hashlib.sha256
            elif alg.endswith('384'):
                hashfunc = hashlib.sha384
            elif alg.endswith('512'):
                hashfunc = hashlib.sha512
            else:
                raise ValueError('Unknown algorithm')
        else:
            raise ValueError('Unsupported algorithm')

        digest = hashfunc(target).digest()

        return b64_encode(digest[:len(digest)//2])


class UserInfoProvider(ResourceProvider):

    def __init__(self, store, header):
        super(UserInfoProvider, self).__init__(store)
        self.header = header

    def get_access_token(self):
        header = list(filter(
            lambda item: item[0].lower() == 'authorization',
            self.header.items()
        ))
        if header:
            key, value = header[0]
            parts = value.split()
            if len(parts) is 2 and parts[0] == 'Bearer':
                return (parts[1], 'bearer')

        return (None, '')

    def handle_request(self, scopes=set(['openid'])):
        try:
            token = self.authorize(scopes)
        except AccessDenied:
            raise  # TODO: return error response
        else:
            if scopes == {'openid'}:
                scopes = token.get_scope()

            owner = token.get_owner()
            user_info = owner.get_user_info(scopes)
            return user_info
