# -*- coding: utf-8 -*-


class IOwner:

    def get_user_info(self, scopes):
        raise NotImplementedError

    def get_sub(self):
        raise NotImplementedError
