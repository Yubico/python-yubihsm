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

from .utils import YubiHsmTestCase, DEFAULT_KEY
from yubihsm.defs import OBJECT, CAPABILITY, ALGORITHM, ORIGIN
from yubihsm.objects import Opaque
import time


class Reset(YubiHsmTestCase):
    def test_reset(self):
        Opaque.put(
            self.session, 0, "Test opaque data", 1, 0, OBJECT.OPAQUE, b"dummyobject"
        )
        self.session.reset_device()
        self.hsm.close()

        time.sleep(5)  # Wait for device to reboot

        self.connect_hsm()  # Re-connect since device restarted.
        self.session = self.hsm.create_session_derived(1, DEFAULT_KEY)
        self.assertEqual(len(self.session.list_objects()), 1)
        auth_key = self.session.get_object(1, OBJECT.AUTHENTICATION_KEY)

        # Check details of default key
        info = auth_key.get_info()
        self.assertEqual(info.capabilities & CAPABILITY.ALL, CAPABILITY.ALL)
        self.assertEqual(info.id, 1)
        self.assertEqual(info.size, 40)
        self.assertEqual(info.domains, 0xFFFF)
        self.assertEqual(info.object_type, OBJECT.AUTHENTICATION_KEY)
        self.assertEqual(info.algorithm, ALGORITHM.AES128_YUBICO_AUTHENTICATION)
        self.assertEqual(info.sequence, 0)
        self.assertEqual(info.origin, ORIGIN.IMPORTED)
        self.assertEqual(info.label, "DEFAULT AUTHKEY CHANGE THIS ASAP")
        self.assertEqual(info.capabilities, info.delegated_capabilities)
