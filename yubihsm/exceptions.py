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

"""Exceptions thrown by this library."""

from .defs import ERROR


class YubiHsmError(Exception):
    """Baseclass for YubiHSM errors."""


class YubiHsmConnectionError(YubiHsmError):
    """The connection to the YubiHSM failed."""


class YubiHsmDeviceError(YubiHsmError):
    """The YubiHSM returned an error code.

    :param int code: The device error code.
    """

    def __init__(self, code: int):
        self.code = ERROR(code)
        super(YubiHsmDeviceError, self).__init__(
            "{0.name} (error code 0x{0.value:02x})".format(self.code)
        )


class YubiHsmInvalidRequestError(YubiHsmError):
    """The request was not able to be sent to the YubiHSM."""


class YubiHsmInvalidResponseError(YubiHsmError):
    """The YubiHSM returned an unexpected response."""


class YubiHsmAuthenticationError(YubiHsmError):
    """Authentication failed."""
