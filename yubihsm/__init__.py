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

"""
Contains the main YubiHsm class used to connect to a YubiHSM device.

See :class:`~yubihsm.core.YubiHsm`.

:Example:

>>> from yubihsm import YubiHsm
... hsm = YubiHsm.connect('http://localhost:12345')
... session = hsm.create_session_derived(1, 'password')
"""


from __future__ import absolute_import
from .core import YubiHsm  # noqa F401


__version__ = "2.1.0-dev0"
