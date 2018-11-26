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

from __future__ import absolute_import, division

from .utils import YubiHsmTestCase
from yubihsm.defs import ALGORITHM, CAPABILITY, OBJECT, COMMAND, ORIGIN
from yubihsm.objects import AsymmetricKey, HmacKey, WrapKey, AuthenticationKey
import uuid
import os


class TestListObjects(YubiHsmTestCase):

    def print_list_objects(self):
        objlist = self.session.list_objects()

        for i in range(len(objlist)):
            print('id: ', '0x%0.4X' % objlist[i].id, ',type: ',
                  OBJECT(objlist[i].object_type).name,
                  '\t,sequence: ', objlist[i].sequence)

        objinfo = objlist[1].get_info()
        print('id: ', '0x%0.4X' % objinfo.id, ',type: ',
              OBJECT(objinfo.object_type).name,
              '\t,sequence: ', objinfo.sequence,
              ',domains: 0x%0.4X' % objinfo.domains,
              ',capabilities: 0x%0.8X' % objinfo.capabilities,
              ',algorithm: ', objinfo.algorithm)

    def key_in_list(self, keytype, algorithm=None):
        dom = None
        cap = 0
        key_label = '%s%s' % (str(uuid.uuid4()),
                              b'\xf0\x9f\x98\x83'.decode('utf8'))

        if keytype == OBJECT.ASYMMETRIC_KEY:
            dom = 0xffff
            key = AsymmetricKey.generate(
                self.session, 0, key_label, dom, cap, algorithm)
        elif keytype == OBJECT.WRAP_KEY:
            dom = 0x01
            key = WrapKey.generate(
                self.session, 0, key_label, dom, cap, algorithm, cap)
        elif keytype == OBJECT.HMAC_KEY:
            dom = 0x01
            key = HmacKey.generate(
                self.session, 0, key_label, dom, cap, algorithm)
        elif keytype == OBJECT.AUTHENTICATION_KEY:
            dom = 0x01
            key = AuthenticationKey.put_derived(
                self.session, 0, key_label, dom, cap, 0,
                b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
                b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
            )

        objlist = self.session.list_objects(object_id=key.id,
                                            object_type=key.object_type)
        self.assertEqual(objlist[0].id, key.id)
        self.assertEqual(objlist[0].object_type, key.object_type)

        objinfo = objlist[0].get_info()
        self.assertEqual(objinfo.id, key.id)
        self.assertEqual(objinfo.object_type, key.object_type)
        self.assertEqual(objinfo.domains, dom)
        self.assertEqual(objinfo.capabilities, cap)
        if algorithm:
            self.assertEqual(objinfo.algorithm, algorithm)

        if key.object_type == OBJECT.AUTHENTICATION_KEY:
            self.assertEqual(objinfo.origin, ORIGIN.IMPORTED)
        else:
            self.assertEqual(objinfo.origin, ORIGIN.GENERATED)

        self.assertEqual(objinfo.label, key_label)

        key.delete()

    def test_keys_in_list(self):
        self.key_in_list(OBJECT.ASYMMETRIC_KEY, ALGORITHM.EC_P256)
        self.key_in_list(OBJECT.WRAP_KEY, ALGORITHM.AES128_CCM_WRAP)
        self.key_in_list(OBJECT.HMAC_KEY, ALGORITHM.HMAC_SHA1)
        self.key_in_list(OBJECT.AUTHENTICATION_KEY)

    def test_list_all_params(self):
        # TODO: this test should check for presence of some things..
        self.session.list_objects(
            object_id=1, object_type=OBJECT.HMAC_KEY, domains=1,
            capabilities=CAPABILITY.ALL, algorithm=ALGORITHM.HMAC_SHA1,
            label='foo'
        )


class TestVarious(YubiHsmTestCase):

    def test_device_info(self):
        device_info = self.hsm.get_device_info()
        self.assertEqual(len(device_info.version), 3)
        self.assertGreater(device_info.serial, 0)
        self.assertGreater(device_info.log_used, 0)
        self.assertGreaterEqual(device_info.log_size, device_info.log_used)
        self.assertGreaterEqual(len(device_info.supported_algorithms),
                                len(ALGORITHM))

    def test_get_pseudo_random(self):
        data = self.session.get_pseudo_random(10)
        self.assertEqual(len(data), 10)
        data2 = self.session.get_pseudo_random(10)
        self.assertEqual(len(data2), 10)
        self.assertNotEqual(data, data2)


class TestEcho(YubiHsmTestCase):

    def plain_echo(self, echo_len):
        echo_buf = os.urandom(echo_len)

        resp = self.hsm.send_cmd(COMMAND.ECHO, echo_buf)

        self.assertEqual(len(resp), echo_len)
        self.assertEqual(resp, echo_buf)

    def secure_echo(self, echo_len):
        echo_buf = os.urandom(echo_len)

        resp = self.session.send_secure_cmd(COMMAND.ECHO, echo_buf)
        self.assertEqual(resp, echo_buf)

    def test_plain_echo(self):
        self.plain_echo(1024)

    def test_secure_echo(self):
        self.secure_echo(1024)

    def test_plain_echo_many(self):
        for i in range(1, 256):
            self.plain_echo(i)
