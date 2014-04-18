# -*- coding: utf-8 -*-

import random
import string
import unittest
import uuid

from py3oauth2.provider import (
    refreshtokengrant,
    authorizationcodegrant,
)

from ..provider import (
    AuthorizationProvider,
    UserInfoProvider
)
from .. import (
    authorizationcodeflow,
    hybridflow,
    implicitflow,
)
from ...userinfo import UserInfo
from . import (
    Client,
    Owner,
    Store,
)


class TestAuthorizationProvider(unittest.TestCase):

    def setUp(self):
        self.store = Store()

    def test_detect_request_class(self):
        inst = AuthorizationProvider(self.store, 'https://example.com/')
        request = {
            'grant_type': 'refresh_token',
        }
        self.assertIs(
            inst.detect_request_class(request),
            refreshtokengrant.Request
        )

        request = {
            'grant_type': 'authorization_code',
        }
        self.assertIs(
            inst.detect_request_class(request),
            authorizationcodegrant.AccessTokenRequest
        )

        request = {
            'grant_type': 'id_token',
        }
        self.assertIsNone(inst.detect_request_class(request))

        request = {
            'response_type': 'code',
        }
        self.assertIs(
            inst.detect_request_class(request),
            authorizationcodeflow.AuthenticationRequest
        )

        request = {
            'response_type': 'code id_token',
        }
        self.assertIs(
            inst.detect_request_class(request),
            hybridflow.AuthenticationRequest
        )

        request = {
            'response_type': 'code token',
        }
        self.assertIs(
            inst.detect_request_class(request),
            hybridflow.AuthenticationRequest
        )

        request = {
            'response_type': 'code id_token token',
        }
        self.assertIs(
            inst.detect_request_class(request),
            hybridflow.AuthenticationRequest
        )

        request = {
            'response_type': 'code id_token refresh_token',
        }
        self.assertIsNone(inst.detect_request_class(request))

        request = {
            'response_type': 'id_token',
        }
        self.assertIs(
            inst.detect_request_class(request),
            implicitflow.Request
        )

        request = {
            'response_type': 'id_token token',
        }
        self.assertIs(
            inst.detect_request_class(request),
            implicitflow.Request
        )

        request = {
            'response_type': 'id_token token refresh_token',
        }
        self.assertIsNone(inst.detect_request_class(request))

        request = {}
        self.assertIsNone(inst.detect_request_class(request))


class TestUserInfoProvider(unittest.TestCase):

    def setUp(self):
        self.store = Store()

        client = Client(str(uuid.uuid4()))

        self.user_info = UserInfo()
        owner = Owner(str(uuid.uuid4()), self.user_info)

        pool = string.ascii_letters + string.digits
        token = ''.join(random.choice(pool) for _ in range(40))
        self.token = self.store.persist_access_token(
            client, owner, token, 'openid', '',
        )

    def test_get_access_token(self):
        inst = UserInfoProvider(self.store, {
            'Authorization': 'Bearer {token}'.format(
                token=self.token.get_token()
            ),
        })

        self.assertEqual(
            inst.get_access_token(),
            (self.token.get_token(), 'bearer')
        )

    def test_get_access_token_unknown(self):
        inst = UserInfoProvider(self.store, {
            'Authorization': 'Unknown {token}'.format(
                token=self.token.get_token()
            ),
        })

        self.assertEqual(inst.get_access_token(), (None, ''))

    def test_handle_request(self):
        inst = UserInfoProvider(self.store, {
            'Authorization': 'Bearer {token}'.format(
                token=self.token.get_token()
            ),
        })
        resp = inst.handle_request(set(['openid']))
        self.assertEqual(resp, self.user_info.filter(set(['openid'])))
