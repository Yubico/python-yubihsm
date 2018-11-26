# Copyright 2016-2018 Yubico AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import

from ..exceptions import YubiHsmConnectionError
from requests.exceptions import RequestException
from six.moves.urllib import parse
import requests


class HttpBackend(object):
    """A backend for communicating with a YubiHSM connector over HTTP."""

    def __init__(self, url='http://localhost:12345', timeout=None):
        """Constructs a new HttpBackend, connecting to the given URL.

        The URL should be a http(s) URL to a running YubiHSM connector.
        By default, the backend will attempt to connect to a connector running
        locally, on the default port.

        :param str url: (optional) The URL to connect to.
        :param timeout: (optional) A timeout in seconds, or a tuple of two
            values to use as connection timeout and request timeout.
        :type timeout: int or tuple[int, int]
        """
        self._url = parse.urljoin(url, '/connector/api')
        self._timeout = timeout

        self._session = requests.Session()
        self._session.headers.update(
            {'Content-Type': 'application/octet-stream'})

    def transceive(self, msg):
        """Send a verbatim message."""
        try:
            resp = self._session.post(
                url=self._url,
                data=msg,
                timeout=self._timeout
            )
            resp.raise_for_status()
            return resp.content
        except RequestException as e:
            raise YubiHsmConnectionError(e)

    def close(self):
        self._session.close()

    def __repr__(self):
        return '{0.__class__.__name__}("{0._url}")'.format(self)
