# -*- coding: utf-8 -*-

import unittest
import uuid

from jwt import JWT
from jwt.jws import JWS

from oidc.provider import UserInfoProvider
from oidc.userinfo import UserInfo
from oidc.tests import (
    Client,
    Owner,
    Store,
)


class TestUserInfoProvider(unittest.TestCase):

    def setUp(self):
        self.store = Store()

        client = Client(str(uuid.uuid4()))
        self.user_info = UserInfo()
        owner = Owner(str(uuid.uuid4()), self.user_info)
        self.token = self.store.issue_access_token(client, owner, {'openid'})

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
