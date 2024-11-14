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
from yubihsm.defs import ALGORITHM, CAPABILITY, AUDIT, ERROR, COMMAND
from yubihsm.objects import HmacKey
from yubihsm.exceptions import YubiHsmDeviceError, YubiHsmInvalidResponseError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from dataclasses import replace
import os
import time
import struct
import pytest


@pytest.fixture(autouse=True, scope="module")
def turn_on_logging(session, info):
    # Enable command audit logging for all commands on YubiHSM versions >= 2.3.1
    # This ensures test independence across different YubiHSM versions
    if info.version >= (2, 3, 1):
        ignored_cmds = [
            COMMAND.ERROR,
            COMMAND.DEVICE_INFO,
            COMMAND.GET_LOG_ENTRIES,
            COMMAND.ECHO,
            COMMAND.SESSION_MESSAGE,
        ]

        if info.version < (2, 4, 0):
            ignored_cmds.extend(
                [
                    COMMAND.PUT_PUBLIC_WRAP_KEY,
                    COMMAND.WRAP_KEY_RSA,
                    COMMAND.UNWRAP_KEY_RSA,
                    COMMAND.EXPORT_WRAPPED_RSA,
                    COMMAND.IMPORT_WRAPPED_RSA,
                ]
            )

        session.set_command_audit(
            {cmd: AUDIT.ON for cmd in COMMAND if cmd not in ignored_cmds}
        )


def test_get_log_entries(session):
    boot, auth, logs = session.get_log_entries()

    last_digest = logs[0].digest
    for i in range(1, len(logs)):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(logs[i].data)
        digest.update(last_digest)
        last_digest = digest.finalize()[:16]
        assert last_digest == logs[i].digest


def test_full_log(session):
    hmackey = HmacKey.generate(
        session,
        0,
        "Test Full Log",
        1,
        CAPABILITY.SIGN_HMAC | CAPABILITY.VERIFY_HMAC,
        ALGORITHM.HMAC_SHA256,
    )

    for i in range(0, 30):
        data = os.urandom(64)
        resp = hmackey.sign_hmac(data)
        assert len(resp) == 32
        assert hmackey.verify_hmac(resp, data)

    boot, auth, logs = session.get_log_entries()

    last_digest = logs[0].digest
    for i in range(1, len(logs)):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(logs[i].data)
        digest.update(last_digest)
        last_digest = digest.finalize()[:16]
        assert last_digest == logs[i].digest

    hmackey.delete()


def test_wrong_chain(session):
    hmackey = HmacKey.generate(
        session,
        0,
        "Test Log hash chain",
        1,
        CAPABILITY.SIGN_HMAC | CAPABILITY.VERIFY_HMAC,
        ALGORITHM.HMAC_SHA256,
    )

    boot, auth, logs = session.get_log_entries()
    last_line = logs.pop()
    session.set_log_index(last_line.number)

    hmackey.sign_hmac(b"hello")
    hmackey.sign_hmac(b"hello")
    hmackey.sign_hmac(b"hello")

    with pytest.raises(ValueError):
        session.get_log_entries(logs.pop())  # Wrong number

    wrong_line = replace(last_line, digest=os.urandom(16))
    with pytest.raises(YubiHsmInvalidResponseError):
        session.get_log_entries(wrong_line)

    hmackey.delete()


def test_forced_log(hsm, session):
    boot, auth, logs = session.get_log_entries()
    last_line = logs.pop()
    session.set_log_index(last_line.number)
    session.set_force_audit(AUDIT.ON)
    assert session.get_force_audit() == AUDIT.ON

    hmackey = HmacKey.generate(
        session,
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
            assert len(resp) == 32
            assert hmackey.verify_hmac(resp, data)
        except YubiHsmDeviceError as e:
            error = e.code
    assert error == ERROR.LOG_FULL
    device_info = hsm.get_device_info()
    assert device_info.log_used == device_info.log_size

    boot, auth, logs = session.get_log_entries(last_line)
    last_line = logs.pop()
    session.set_log_index(last_line.number)
    session.set_force_audit(AUDIT.OFF)
    assert session.get_force_audit() == AUDIT.OFF

    for i in range(0, 32):
        data = os.urandom(64)
        resp = hmackey.sign_hmac(data)
        assert len(resp) == 32
        assert hmackey.verify_hmac(resp, data)

    hmackey.delete()


def test_logs_after_reset(hsm, connect_hsm, session, info):
    session.reset_device()
    hsm.close()

    time.sleep(5)  # Wait for device to reboot

    with connect_hsm() as hsm:
        with hsm.create_session_derived(1, DEFAULT_KEY) as session:
            boot, auth, logs = session.get_log_entries()

    # Check the version of the YubiHSM and verify the number of log entries.
    # YubiHSM versions >= 2.3.1 have command audit logging disabled per default,
    # so they will only have two initial logs: the boot and reset line.
    # Versions below 2.3.1 are expected to have four log entries: the boot line,
    # reset line, create_session and authenticate_session cmd.
    if info.version < (2, 3, 1):
        assert 4 == len(logs)
    else:
        assert 2 == len(logs)

    # Reset line
    assert logs.pop(0).data == b"\0\1" + b"\xff" * 14

    # Boot line
    assert logs.pop(0).data == struct.pack("!HBHHHHBL", 2, 0, 0, 0xFFFF, 0, 0, 0, 0)

    if info.version < (2, 3, 1):
        assert logs.pop(0).command == COMMAND.CREATE_SESSION
        assert logs.pop(0).command == COMMAND.AUTHENTICATE_SESSION
