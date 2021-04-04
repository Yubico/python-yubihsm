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
from yubihsm.defs import ALGORITHM, CAPABILITY, AUDIT, ERROR, COMMAND
from yubihsm.objects import HmacKey
from yubihsm.exceptions import YubiHsmDeviceError, YubiHsmInvalidResponseError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import time
import struct


class TestLogs(YubiHsmTestCase):
    def test_get_log_entries(self):
        boot, auth, logs = self.session.get_log_entries()

        last_digest = logs[0].digest
        for i in range(1, len(logs)):
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(logs[i].data)
            digest.update(last_digest)
            last_digest = digest.finalize()[:16]
            self.assertEqual(last_digest, logs[i].digest)

    def test_full_log(self):
        hmackey = HmacKey.generate(
            self.session,
            0,
            "Test Full Log",
            1,
            CAPABILITY.SIGN_HMAC | CAPABILITY.VERIFY_HMAC,
            ALGORITHM.HMAC_SHA256,
        )

        for i in range(0, 30):
            data = os.urandom(64)
            resp = hmackey.sign_hmac(data)
            self.assertEqual(len(resp), 32)
            self.assertTrue(hmackey.verify_hmac(resp, data))

        boot, auth, logs = self.session.get_log_entries()

        last_digest = logs[0].digest
        for i in range(1, len(logs)):
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(logs[i].data)
            digest.update(last_digest)
            last_digest = digest.finalize()[:16]
            self.assertEqual(last_digest, logs[i].digest)

    def test_wrong_chain(self):
        hmackey = HmacKey.generate(
            self.session,
            0,
            "Test Log hash chain",
            1,
            CAPABILITY.SIGN_HMAC | CAPABILITY.VERIFY_HMAC,
            ALGORITHM.HMAC_SHA256,
        )

        boot, auth, logs = self.session.get_log_entries()
        last_line = logs.pop()
        self.session.set_log_index(last_line.number)

        hmackey.sign_hmac(b"hello")
        hmackey.sign_hmac(b"hello")
        hmackey.sign_hmac(b"hello")

        with self.assertRaises(ValueError):
            self.session.get_log_entries(logs.pop())  # Wrong number

        wrong_line = last_line._replace(digest=os.urandom(16))
        with self.assertRaises(YubiHsmInvalidResponseError):
            self.session.get_log_entries(wrong_line)

    def test_forced_log(self):
        boot, auth, logs = self.session.get_log_entries()
        last_line = logs.pop()
        self.session.set_log_index(last_line.number)
        self.session.set_force_audit(AUDIT.ON)
        self.assertEqual(self.session.get_force_audit(), AUDIT.ON)

        hmackey = HmacKey.generate(
            self.session,
            0,
            "Test Force Log",
            1,
            CAPABILITY.SIGN_HMAC | CAPABILITY.VERIFY_HMAC,
            ALGORITHM.HMAC_SHA256,
        )

        error = 0
        for i in range(0, 32):
            try:
                data = os.urandom(64)
                resp = hmackey.sign_hmac(data)
                self.assertEqual(len(resp), 32)
                self.assertTrue(hmackey.verify_hmac(resp, data))
            except YubiHsmDeviceError as e:
                error = e.code
        self.assertEqual(error, ERROR.LOG_FULL)
        device_info = self.hsm.get_device_info()
        self.assertEqual(device_info.log_used, device_info.log_size)

        boot, auth, logs = self.session.get_log_entries(last_line)
        last_line = logs.pop()
        self.session.set_log_index(last_line.number)
        self.session.set_force_audit(AUDIT.OFF)
        self.assertEqual(self.session.get_force_audit(), AUDIT.OFF)

        for i in range(0, 32):
            data = os.urandom(64)
            resp = hmackey.sign_hmac(data)
            self.assertEqual(len(resp), 32)
            self.assertTrue(hmackey.verify_hmac(resp, data))

    def test_logs_after_reset(self):
        self.session.reset_device()
        self.hsm.close()
        time.sleep(5)  # Wait for device to reboot

        self.connect_hsm()  # Re-connect since device restarted.
        self.session = self.hsm.create_session_derived(1, DEFAULT_KEY)
        boot, auth, logs = self.session.get_log_entries()
        self.assertEqual(4, len(logs))

        # Reset line
        self.assertEqual(logs.pop(0).data, b"\0\1" + b"\xff" * 14)

        # Boot line
        self.assertEqual(
            logs.pop(0).data, struct.pack("!HBHHHHBL", 2, 0, 0, 0xFFFF, 0, 0, 0, 0)
        )

        self.assertEqual(logs.pop(0).command, COMMAND.CREATE_SESSION)
        self.assertEqual(logs.pop(0).command, COMMAND.AUTHENTICATE_SESSION)
