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

from six.moves.urllib import parse
import re


def get_backend(url=None):
    """Returns a backend suitable for the given URL."""
    url = url or "http://localhost:12345"
    parsed = parse.urlparse(url)

    try:
        if parsed.scheme == "yhusb":
            from .usb import UsbBackend

            serial = re.match(r"serial=(\d+)", parsed.netloc)
            if serial:
                return UsbBackend(int(serial.group(1)))
            elif not parsed.netloc:  # On anything else, fall through to error.
                return UsbBackend()
        elif parsed.scheme in ("http", "https"):
            from .http import HttpBackend

            return HttpBackend(url, (10, 600))
    except ImportError:
        raise ValueError(
            'Unable to initialize backend for scheme "%s", are '
            "required dependencies installed?" % parsed.scheme
        )

    raise ValueError("Invalid YubiHSM backend URL.")
