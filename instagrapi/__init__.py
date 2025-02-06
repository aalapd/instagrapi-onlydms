import logging
from urllib.parse import urlparse

import requests
from urllib3.exceptions import InsecureRequestWarning

from instagrapi.mixins.account import AccountMixin
from instagrapi.mixins.auth import LoginMixin
from instagrapi.mixins.bloks import BloksMixin
from instagrapi.mixins.challenge import ChallengeResolveMixin
from instagrapi.mixins.direct import DirectMixin
from instagrapi.mixins.password import PasswordMixin
from instagrapi.mixins.private import PrivateRequestMixin
from instagrapi.mixins.public import (
    ProfilePublicMixin,
    PublicRequestMixin,
    TopSearchesPublicMixin,
)
from instagrapi.mixins.totp import TOTPMixin
from instagrapi.mixins.user import UserMixin

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Used as fallback logger if another is not provided.
DEFAULT_LOGGER = logging.getLogger("instagrapi")


class Client(
    PublicRequestMixin,
    ChallengeResolveMixin,
    PrivateRequestMixin,
    TopSearchesPublicMixin,
    ProfilePublicMixin,
    LoginMixin,
    UserMixin,
    AccountMixin,
    DirectMixin,
    PasswordMixin,
    BloksMixin,
    TOTPMixin,
):
    proxy = None

    def __init__(
        self,
        settings: dict = {},
        proxy: str = None,
        delay_range: list = None,
        logger=DEFAULT_LOGGER,
        **kwargs,
    ):

        super().__init__(**kwargs)

        self.settings = settings
        self.logger = logger
        self.delay_range = delay_range

        self.set_proxy(proxy)

        self.init()

    def set_proxy(self, dsn: str):
        if dsn:
            assert isinstance(
                dsn, str
            ), f'Proxy must been string (URL), but now "{dsn}" ({type(dsn)})'
            self.proxy = dsn
            proxy_href = "{scheme}{href}".format(
                scheme="http://" if not urlparse(self.proxy).scheme else "",
                href=self.proxy,
            )
            self.public.proxies = self.private.proxies = {
                "http": proxy_href,
                "https": proxy_href,
            }
            return True
        self.public.proxies = self.private.proxies = {}
        return False
