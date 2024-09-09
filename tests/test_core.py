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
Tests of the core.py module. Currently just includes test of functions that
don't require mocking.
"""

import struct
import unittest

from yubihsm.core import (
    DeviceInfo,
    _derive,
    _unpad_resp,
    LogEntry,
    YubiHsm,
    AuthSession,
)
from yubihsm.defs import COMMAND, CAPABILITY, ALGORITHM
from yubihsm.backends import YhsmBackend
from unittest.mock import patch, MagicMock, call
from yubihsm.exceptions import YubiHsmDeviceError, YubiHsmInvalidResponseError

_DEVICE_INFO = b"\x02\x00\x00\x00s5m>>\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./"  # noqa
_TRANSCEIVE_DEVICE_INFO = b"\x86\x008\x02\x00\x00\x00s4\xbc>\x04\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./"  # noqa


def get_backend():
    return MagicMock(YhsmBackend)


def simple_urandom(length):
    """See https://xkcd.com/221/"""
    return b"\x00" * length


@patch("os.urandom", side_effect=simple_urandom)
def get_mocked_session(patch):
    """
    Create a fake session by mocking
    the backend.transceive function
    """
    mocked_backend = get_backend()
    mocked_backend.transceive.side_effect = [
        _TRANSCEIVE_DEVICE_INFO,  # get_device_info is called during initialization
        b"\x83\x00\x11\x00\x05MV1\xc9\x18o\x802%\xed\x8a2$\xf2\xcf",
        b"\x84\x00\x00",
    ]
    hsm = YubiHsm(backend=mocked_backend)

    auth_key_id = 1
    key_enc = b"\t\x0bG\xdb\xedYVT\x90\x1d\xee\x1c\xc6U\xe4 "
    key_mac = b"Y/\xd4\x83\xf7Y\xe2\x99\t\xa0LE\x05\xd2\xce\n"
    return hsm.create_session(auth_key_id, key_enc, key_mac)


class TestDeviceInfo(unittest.TestCase):
    """Test the functionality of the DeviceInfo class"""

    def test_class(self):
        """
        Full testing of the Device Info class
        """
        info = DeviceInfo.parse(_DEVICE_INFO)
        self.assertEqual(info.version, (2, 0, 0))
        self.assertEqual(info.serial, 7550317)
        self.assertEqual(info.log_size, 62)
        self.assertEqual(info.log_used, 62)
        self.assertEqual(len(info.supported_algorithms), 47)


class TestDeriveFct(unittest.TestCase):
    """
    Test the functionality of the private method _derive. If we decide not to
    test private functions, this can be removed.
    """

    def test_success(self):
        """
        Make sure the function works on a test case that should succeed
        """
        context = b"\x0c\xf4\xf5L\xb9\xdfY["
        t = 0x04
        key = b"0xff0xff0x120xff0xff0xff0xff0xaf"
        rval = _derive(key, t, context)
        self.assertEqual(rval, b"W\xa0\x7f1\xb9\x13\xbc\xe5\xff\x066J\x0e9Fz")

    def test_value_error(self):
        """
        Make sure the test fails when an unsupported value
        """
        context = b"\x0c\xf4\xf5L\xb9\xdfY["
        t = 0x04
        key = b"0xff0xff0x120xff0xff0xff0xff0xaf"
        self.assertRaises(ValueError, _derive, key, t, context, 0x60)


class TestUnpad(unittest.TestCase):
    """
    Test the functionality of the private method _unpad. If we decide not to
    test private functions, this can be removed.
    """

    def test_invalid_len(self):
        """Check if the response length is invalid"""
        resp = b"\x02\x7f"
        cmd = COMMAND.SIGN_ECDSA
        self.assertRaises(YubiHsmInvalidResponseError, _unpad_resp, resp, cmd)
        resp = b"\x14\x00\x06\x00|\x00\xff"
        self.assertRaises(YubiHsmInvalidResponseError, _unpad_resp, resp, cmd)

    def test_device_error(self):
        """Check if the length of the response doesn't match promised length"""
        cmd = COMMAND.ERROR
        resp = b"\x7f\x00\x01\x00\x01\x00>"
        self.assertRaises(YubiHsmDeviceError, _unpad_resp, resp, cmd)

    def test_invalid_rcommand(self):
        """Throw error if the response command doesn't match the
        command sent | 0x80"""
        cmd = COMMAND.AUTHENTICATE_SESSION
        resp = struct.pack("!BHHH", cmd - 1, 1, 1, 62)
        self.assertRaises(YubiHsmInvalidResponseError, _unpad_resp, resp, cmd)

    def test_success(self):
        """Otherwise, succeed"""
        cmd = COMMAND.AUTHENTICATE_SESSION
        resp = b"\x84\x00\x02\x00\x01\x00\x1d\x00\x04"
        rval = _unpad_resp(resp, cmd)
        self.assertEqual(rval, b"\x00\x01")


class TestLogEntry(unittest.TestCase):
    """
    Full testing of the LogEntry class
    """

    def test_construction(self):
        """Use classmethod `parse` to construct log entry from data"""

        # Decide on values
        vals = 513, 250, 1020, 56, 800, 900, 20, 1023, b"abcdefghiklmnop0"
        keys = (
            "number",
            "command",
            "length",
            "session_key",
            "target_key",
            "second_key",
            "result",
            "tick",
            "digest",
        )

        # Pack it up for parsing
        data = struct.pack("!HBHHHHBL16s", *vals)

        # Use the `parse` alternate constructor
        log = LogEntry.parse(data)
        for key, val in zip(keys, vals):
            self.assertEqual(getattr(log, key), val)

        # Make sure __init__ and parse give you the same result
        self.assertEqual(LogEntry(**dict(zip(keys, vals))), log)


class TestLogCorrect(unittest.TestCase):
    """
    Full coverage tests of the log class. Includes construction, checks
    for errors, and validation
    """

    FORMAT = "!HBHHHHBL16s"

    # The first 2 entries in the log are provided below, along with a
    # version of log 2 with a tampered hash
    log1_vals = (
        2,
        0,
        0,
        65535,
        0,
        0,
        0,
        0,
        b"\xf6\x96\x90n[9)\xc6<\xa6\xf1\n\x83\xd2\xa0\xcc",
    )

    log2_vals = (
        3,
        3,
        10,
        65535,
        1,
        65535,
        131,
        35,
        b'"d\xd4Q\xb5\xef\xf5\xdf\xa9LTO3\xb7\x87\xa9',
    )

    # Log 2 is valid, aside from its hash, which doesn't match
    log2_badvals = (
        3,
        3,
        10,
        65535,
        1,
        65535,
        131,
        35,
        b'"d\xd4Q\xb5\xef\xf5\xdf\xa9LTO3\xb7\x87\xa8',
    )

    log1 = struct.pack(FORMAT, *log1_vals)
    log2 = struct.pack(FORMAT, *log2_vals)
    log2_bad = struct.pack(FORMAT, *log2_badvals)

    e1 = LogEntry.parse(log1)
    e2 = LogEntry.parse(log2)
    e2_bad = LogEntry.parse(log2_bad)

    def test_logvalidation(self):
        """Make sure we can validate correct, sequential entries"""
        self.assertTrue(self.e2.validate(self.e1))

    def test_unorderedloginvalid(self):
        """Entries can't validate if out of order"""
        self.assertRaises(ValueError, self.e1.validate, self.e2)

    def test_tamperedhash(self):
        """Bad hashes can be detected"""
        self.assertFalse(self.e2_bad.validate(self.e1))

    def test_data(self):
        """Check that the data property works"""
        self.assertTrue(self.e1.data == self.log1[:-16])

    def test_initializer(self):
        """
        Check that using the default initializer gives the same
        result as using the pack constructor
        """
        self.assertTrue(self.e1 == LogEntry(*self.log1_vals))


class TestYubiHsm(unittest.TestCase):
    @patch("yubihsm.core.YubiHsm.create_session")
    def test_create_session_derived(self, item):
        """
        Test if create_session_derived calls create_session correctly
        """

        auth_key_id = 1
        password = "password"
        expect_enc = b"\t\x0bG\xdb\xedYVT\x90\x1d\xee\x1c\xc6U\xe4 "
        expect_mac = b"Y/\xd4\x83\xf7Y\xe2\x99\t\xa0LE\x05\xd2\xce\n"

        # Note: get_device_info gets called during initialization
        # which is why we mock the transceive function.
        backend = get_backend()
        backend.transceive.return_value = _TRANSCEIVE_DEVICE_INFO

        hsm = YubiHsm(backend)
        hsm.create_session_derived(auth_key_id, password)

        hsm.create_session.assert_called_once_with(auth_key_id, expect_enc, expect_mac)

    def test_get_device_info_mock_transceive(self):
        """
        Test get_device_info function by mocking the transceive function
        """

        backend = get_backend()
        backend.transceive.return_value = _TRANSCEIVE_DEVICE_INFO

        hsm = YubiHsm(backend)

        info = hsm.get_device_info()
        hsm._backend.transceive.assert_has_calls(
            [
                call(b"\x06\x00\x00"),  # first call during YubiHSM::__init__
                call(b"\x06\x00\x00"),
            ]
        )

        self.assertEqual(info.version, (2, 0, 0))
        self.assertEqual(info.serial, 7550140)
        self.assertEqual(info.log_size, 62)
        self.assertEqual(info.log_used, 4)
        self.assertEqual(len(info.supported_algorithms), 47)


class TestAuthsession(unittest.TestCase):
    def test_list_objects1(self):
        """
        Test the first half of the list_objects function:
        We process the input and make our query to the send_cmd
        """
        # Create fake session, and mock the return from a call to side_effect
        session = MagicMock(AuthSession)
        session.send_secure_cmd.side_effect = [b"\x00\x01\x02\x00V7\x03\x00"]

        # Run the function, and make sure the correct call is made to secure_cmd
        AuthSession.list_objects(
            session,
            object_id=2,
            object_type=1,
            domains=65535,
            capabilities=CAPABILITY.ALL,
            algorithm=ALGORITHM.HMAC_SHA384,
        )

        # We care only about the value sent; we aren't checking the return value
        # from send_secure_cmd
        session.send_secure_cmd.assert_called_with(
            72,
            b"\x01\x00\x02\x02\x01\x03\xff\xff\x04\x00\xff\xff\xff\xff\xff\xff\xff\x05\x15",  # noqa E501
        )

    def test_list_objects2(self):
        """
        Test the second half of list_objects(): process the response from the
        send_cmd function and return the list of objects
        """
        list_objects = AuthSession.list_objects
        session = MagicMock(AuthSession)
        session.send_secure_cmd.return_value = b"\x00\x01\x02\x00d\x8f\x03\x00\x00\x01\x03\x00\x00\x04\x05\x00\x00\x05\x05\x00\x00\x05\x03\x00"  # noqa

        # The input to the below function doesn't matter;
        # it's overwritten by the return value listed above
        objlist = list_objects(session)

        # Finally, make sure we decode the results correctly
        # Not the best way to check, but it is succinct
        self.assertEqual(
            objlist.__repr__(),
            "[AuthenticationKey(id=1), AsymmetricKey(id=25743), AsymmetricKey(id=1), HmacKey(id=4), HmacKey(id=5), AsymmetricKey(id=5)]",  # noqa E501
        )

    def test__create_session_patch_transceive(self):
        """
        Tests the entire authsession generation codebase, by mocking just
        os.urandom and the transceive method.
        This test should probably be broken up later.
        """
        authsession = get_mocked_session()
        # Create session should make two calls to transceive.
        # First call was to create session. Second was to authenticate session.
        calls = [
            call(b"\x03\x00\n\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"),
            call(b"\x04\x00\x11\x00\x1c\xe7U.\x0fyv\xdb\xcc!\x98\xfd\x15\\3Z"),
        ]

        authsession._hsm._backend.transceive.assert_has_calls(calls)

    def test_close_session(self):
        """
        Test the close session command; only tests output to send_secure_cmd
        not to transceive
        """

        session = get_mocked_session()
        session.send_secure_cmd = MagicMock(session.send_secure_cmd)

        session.close()
        session.send_secure_cmd.assert_called_once_with(COMMAND.CLOSE_SESSION)

    def test_reset(self):
        """
        Tests the reset command; only tests output to send_secure_cmd
        not to transceive
        """
        session = get_mocked_session()
        session.send_secure_cmd = MagicMock(session.send_secure_cmd)
        session.send_secure_cmd.return_value = b""

        session.reset_device()

        session.send_secure_cmd.assert_called_with(COMMAND.RESET_DEVICE)

    def test_reset_error(self):
        """
        Make sure reset command throws error if nonempty response is returned
        """

        session = get_mocked_session()
        session.send_secure_cmd = MagicMock(session.send_secure_cmd)
        session.send_secure_cmd.return_value = b"\00"

        self.assertRaises(YubiHsmInvalidResponseError, session.reset_device)
