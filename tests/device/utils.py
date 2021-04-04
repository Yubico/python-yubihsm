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

from __future__ import print_function, division

from yubihsm import YubiHsm
from yubihsm.defs import BRAINPOOLP256R1, BRAINPOOLP384R1, BRAINPOOLP512R1
from cryptography.hazmat.primitives.asymmetric import ec

import unittest
import time
import os

# Register Brainpool curves
ec._CURVE_TYPES["brainpoolP256r1"] = BRAINPOOLP256R1
ec._CURVE_TYPES["brainpoolP384r1"] = BRAINPOOLP384R1
ec._CURVE_TYPES["brainpoolP512r1"] = BRAINPOOLP512R1


DEFAULT_KEY = "password"


@unittest.skipIf(os.environ.get("BACKEND", None) == "NONE", "Skipping device tests.")
class YubiHsmTestCase(unittest.TestCase):
    _HAS_RESET = False

    def connect_hsm(self):
        self.hsm = YubiHsm.connect(os.environ.get("BACKEND", None))
        self.info = self.hsm.get_device_info()

    def require_version(self, version, message=None):
        if self.info.version < version:
            m = "Requires version " + ".".join(map(str, version))
            if message:
                m += ": " + message
            self.skipTest(m)

    def setUp(self):
        self.connect_hsm()
        self.session = self.hsm.create_session_derived(1, DEFAULT_KEY)
        if not YubiHsmTestCase._HAS_RESET:
            print("RESETTING DEVICE!!!!")
            self.session.reset_device()
            YubiHsmTestCase._HAS_RESET = True
            time.sleep(5)
            self.setUp()

    def tearDown(self):
        self.session.close()
        del self.session

        self.hsm.close()
        del self.hsm, self.info
