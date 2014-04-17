# -*- coding: utf-8 -*-


class IOwner:

    def get_idtoken(self, scopes):
        raise NotImplementedError
