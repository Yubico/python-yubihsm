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

from . import DEFAULT_KEY
from yubihsm.defs import OBJECT, CAPABILITY, ALGORITHM, ORIGIN
from yubihsm.objects import Opaque
import time


def test_reset(hsm, session, connect_hsm):
    Opaque.put(
        session,
        0,
        "Test opaque data",
        1,
        CAPABILITY.NONE,
        ALGORITHM.OPAQUE_DATA,
        b"dummyobject",
    )
    session.reset_device()
    hsm.close()

    time.sleep(5)  # Wait for device to reboot

    with connect_hsm() as hsm:  # Re-connect since device restarted.
        with hsm.create_session_derived(1, DEFAULT_KEY) as session:
            assert len(session.list_objects()) == 1
            auth_key = session.get_object(1, OBJECT.AUTHENTICATION_KEY)

            # Check details of default key
            info = auth_key.get_info()

    assert info.capabilities & CAPABILITY.ALL == CAPABILITY.ALL
    assert info.id == 1
    assert info.size == 40
    assert info.domains == 0xFFFF
    assert info.object_type == OBJECT.AUTHENTICATION_KEY
    assert info.algorithm == ALGORITHM.AES128_YUBICO_AUTHENTICATION
    assert info.sequence == 0
    assert info.origin == ORIGIN.IMPORTED
    assert info.label == "DEFAULT AUTHKEY CHANGE THIS ASAP"
    assert info.capabilities == info.delegated_capabilities
