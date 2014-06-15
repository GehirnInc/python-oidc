# -*- coding: utf-8 -*-

from oidc.provider import UserInfoProvider
from oidc.tests import TestBase


class TestUserInfoProvider(TestBase):

    def setUp(self):
        super().setUp()

        self.token = self.store.issue_access_token(self.client,
                                                   self.owner,
                                                   {'openid'})

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
