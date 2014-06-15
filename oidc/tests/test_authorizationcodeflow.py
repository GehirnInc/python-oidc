# -*- coding: utf-8 -*-

import json

from jwt.jwt import JWT

from oidc.tests import (
    mock,
    TestBase,
)


class AccessTokenRequestTest(TestBase):

    @property
    def target(self):
        from oidc.authorizationcodeflow import AccessTokenRequest
        return AccessTokenRequest

    def setUp(self):
        super().setUp()

        self.code = self.store.issue_authorization_code(self.client,
                                                        self.owner,
                                                        {'openid', 'scope'})

    def test_answer(self):
        inst = self.target()
        inst.update({
            'client_id': self.client.id,
            'grant_type': 'authorization_code',
            'code': self.code.get_code(),
        })
        inst.validate()

        with mock.patch.object(self.provider, 'authorize_client',
                               return_value=True):
            resp = inst.answer(self.provider, self.owner)

        jwt = JWT(self.jwkset.copy())

        self.assertTrue(jwt.verify(resp.id_token))

        id_token = json.loads(jwt.decode(resp.id_token).decode('utf8'))
        self.assertEqual(
            id_token['at_hash'],
            self.provider.left_hash(self.client.get_jws_alg(),
                                    resp.access_token))
