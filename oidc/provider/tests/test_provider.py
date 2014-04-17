# -*- coding: utf-8 -*-

import random
import string
import unittest
import uuid

from ..provider import UserInfoProvider
from ...userinfo import UserInfo
from . import (
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
