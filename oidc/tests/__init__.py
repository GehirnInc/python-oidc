# -*- coding: utf-8 -*-

import base64
import os
import unittest
import uuid
from datetime import (
    datetime,
    timedelta,
)
try:
    from unittest import mock
except ImportError:
    import mock

import jwt.jwk
import jwt.jwt

from oidc.interfaces import (
    ClientType,
    IAccessToken,
    IAuthorizationCode,
    IClient,
    IOwner,
    IStore,
)
from oidc.provider import AuthorizationProvider
from oidc.userinfo import UserInfo

__all__ = ['mock', 'TestBase']


class Owner(IOwner):

    def __init__(self, id, user_info):
        self.id = id
        self.user_info = user_info

    def get_sub(self):
        return self.id

    def get_user_info(self, scopes):
        return self.user_info.filter(scopes)


class Client(IClient):

    def __init__(self, id, redirect_uri, type):
        self.id = id
        self.redirect_uri = redirect_uri
        self.type = type

    def get_id(self):
        return self.id

    def get_redirect_uri(self):
        return self.redirect_uri

    def get_type(self):
        return self.type

    def get_jws_alg(self):
        return 'RS512'


class AccessToken(IAccessToken):

    def __init__(self, client, owner, scope, expires_in):
        self.client = client
        self.owner = owner
        self.token = base64.b64encode(os.urandom(16)).decode('utf8')
        self.expires_in = expires_in
        self.scope = scope
        self.refresh_token = base64.b64encode(os.urandom(16)).decode('utf8')
        self.issued_at = datetime.utcnow()

    def get_client(self):
        return self.client

    def get_owner(self):
        return self.owner

    def get_token(self):
        return self.token

    def get_type(self):
        return 'bearer'

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return self.issued_at + timedelta(seconds=self.get_expires_in())

    def get_scope(self):
        return self.scope

    def get_refresh_token(self):
        return self.refresh_token


class AuthorizationCode(IAuthorizationCode):

    def __init__(self, client, owner, scope):
        self.client = client
        self.owner = owner
        self.code = base64.b64encode(os.urandom(16)).decode('utf8')
        self.scope = scope
        self.used = False

    def get_client(self):
        return self.client

    def get_owner(self):
        return self.owner

    def get_code(self):
        return self.code

    def get_scope(self):
        return self.scope

    def is_active(self):
        return not self.used

    def deactivate(self):
        self.used = True


class Store(IStore):

    def __init__(self):
        self.clients = dict()
        self.access_tokens = dict()
        self.refresh_tokens = dict()
        self.authorization_codes = dict()

    def persist_client(self, client):
        self.clients[client.get_id()] = client

    def get_client(self, client_id):
        return self.clients.get(client_id)

    def issue_access_token(self, client, owner, scope):
        tokenobj = AccessToken(client, owner, scope, 3600)
        self.access_tokens[tokenobj.get_token()] = tokenobj
        if tokenobj.get_refresh_token():
            self.refresh_tokens[tokenobj.get_refresh_token()] = tokenobj

        return tokenobj

    def discard_access_token(self, token):
        del self.access_tokens[token.get_token()]

    def get_access_token(self, token):
        return self.access_tokens.get(token)

    def get_access_token_by_refresh_token(self, refresh_token):
        return self.refresh_tokens.get(refresh_token)

    def issue_authorization_code(self, client, owner, scope):
        codeobj = AuthorizationCode(client, owner, scope)
        self.authorization_codes[codeobj.get_code()] = codeobj
        return codeobj

    def get_authorization_code(self, code):
        return self.authorization_codes.get(code)


class TestBase(unittest.TestCase):

    def setUp(self):
        self.store = Store()

        self.client = Client(str(uuid.uuid4()),
                             'https://example.com/cb',
                             ClientType.CONFIDENTIAL)
        self.store.persist_client(self.client)

        self.jwkset = jwt.jwk.JWKSet()
        self.jwkset.append(jwt.jwk.JWK.from_dict({
            'e': 'AQAB',
            'n': 'oDqMv8nB2v3S4mYU0NEa3h8AX1fh2KBDQrKtD4coCTbNXIIEP7p2Jd8F_SWY'
                 'V00CdvlySb-OGQ0WtlfHQyJZy3pDeWexfoWgd_7lar0cj72WSBS6YLM465YF'
                 'KVMMGA5PfWEqx8Q4XTdAzGGtJNZWBEGoiA7CLcsB_L3FHpMEENNZLJRzjE-5'
                 'bRyfeCu02J9GlBK_5i3-eTjKqqMjxjvaTNpisA5b9-tmVcb3UZBEojmtYqR4'
                 '057uZUuqqTzMFD78AN7h9tD_r9p7fMQ-GZbFOxYTrq5luKz1adcbJJIPa-vV'
                 'HRizyRgMbcUEwFJ6jwbtlr8VV1DNCEcW-bn0RkHJpw',
            'kty': 'RSA',
            'd': 'aQnZCUWnevuYyuhmzvm15lVmdhpzqQJu9YOSpjJRUbEGcZWeWXTQTUVmdKy3'
                 'sMuASSSAAs67xbpp4EGtFFqpiRXus-EBX9MT_nYwSYgN-EEuCrTj9c6oCvD_'
                 'EzcpH4AKJkSTuf_tf1ZgeVuzGQoVu5abeA5Mx55lAB4b4k44hRouVFBIPdKq'
                 'bnCWLciTUrsQ8fk3w49Cdlt4kwu6a1xsOtDtmg4b_vKzubFz_DaasrHlFadn'
                 '35r6NXQW7YNF3lM8mH0trPWm00B8GBTVX3Lvuk0maRhbVgWkhJur9ckR5_tO'
                 'LkfAP0E75Ftcadj7Dyi8fj4C6ULWt33ALjZMLEjpOQ'
        }))

        self.provider = AuthorizationProvider(self.store,
                                              'https://provider.example.com/',
                                              self.jwkset)

        self.user_info = UserInfo()
        self.user_info.update({
            'name': 'yosida95',
            'give_name': 'Kohei',
            'family_name': 'Yoshida',
            'website': 'https://yosida95.com/',
        })
        self.owner = Owner(str(uuid.uuid4()), self.user_info)
