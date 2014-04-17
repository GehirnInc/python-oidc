# -*- coding: utf-8 -*-

import random
import string
import unittest
import uuid

from ..provider import UserInfoProvider
from . import (
    Client,
    Owner,
    Store,
)


class TestUserInfoProvider(unittest.TestCase):

    def setUp(self):
        self.store = Store()

        client = Client(str(uuid.uuid4()))
        owner = Owner(str(uuid.uuid4()))

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
