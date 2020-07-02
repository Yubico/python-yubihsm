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

"""Core classes for YubiHSM communication."""


from __future__ import absolute_import, division

from . import utils
from .defs import COMMAND, ALGORITHM, LIST_FILTER, OPTION, AUDIT
from .backends import get_backend
from .objects import YhsmObject, _label_pack, LABEL_LENGTH
from .exceptions import (
    YubiHsmDeviceError,
    YubiHsmInvalidRequestError,
    YubiHsmInvalidResponseError,
    YubiHsmAuthenticationError,
    YubiHsmConnectionError,
)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, cmac, constant_time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.utils import int_to_bytes
from hashlib import sha256
from collections import namedtuple
import os
import six
import struct


KEY_ENC = 0x04
KEY_MAC = 0x06
KEY_RMAC = 0x07
CARD_CRYPTOGRAM = 0x00
HOST_CRYPTOGRAM = 0x01

MAX_MSG_SIZE = 2048 - 1


def _derive(key, t, context, L=0x80):
    # this only supports aes128
    if L != 0x80 and L != 0x40:
        raise ValueError("L must be 0x40 or 0x80")

    i = b"\0" * 11 + struct.pack("!BBHB", t, 0, L, 1) + context

    c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
    c.update(i)
    return c.finalize()[: L // 8]


def _unpad_resp(resp, cmd):
    if len(resp) < 3:
        raise YubiHsmInvalidResponseError("Wrong length")
    rcmd, length = struct.unpack("!BH", resp[:3])
    if len(resp) < length + 3:
        raise YubiHsmInvalidResponseError("Wrong length")
    if rcmd == COMMAND.ERROR:
        raise YubiHsmDeviceError(six.indexbytes(resp, 3))
    elif rcmd != cmd | 0x80:
        raise YubiHsmInvalidResponseError("Wrong command in response")
    return resp[3 : length + 3]


def x963_kdf(hash, shsee, shsss, length):
    output = b""

    for i in range(0, length // hash.digest_size + 1):
        digest = hashes.Hash(hash, backend=default_backend())
        digest.update(shsee)
        digest.update(shsss)
        digest.update(struct.pack("!L", i + 1))
        output += digest.finalize()

    return output[:length]


class YubiHsm(object):
    """An unauthenticated connection to a YubiHSM."""

    def __init__(self, backend):
        """Constructs a YubiHSM connected to the given backend.

        :param backend: A backend used to communicate with a YubiHSM.
        """
        self._backend = backend

    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.close()

    def close(self):
        """Disconnect from the backend, freeing any resources in use by it."""
        if self._backend:
            self._backend.close()
            self._backend = None

    def _transceive(self, msg):
        if len(msg) > MAX_MSG_SIZE:
            raise YubiHsmInvalidRequestError("Message too long.")
        return self._backend.transceive(msg)

    def send_cmd(self, cmd, data=b""):
        """Encode and send a command byte and its associated data.

        :param COMMAND cmd: The command to send.
        :param bytes data: The command payload to send.
        :return: The response data from the YubiHSM.
        :rtype: bytes
        """
        msg = struct.pack("!BH", cmd, len(data)) + data
        return _unpad_resp(self._transceive(msg), cmd)

    def get_device_info(self):
        """Get general device information from the YubiHSM.

        :return: Device information.
        :rtype: DeviceInfo
        """
        return DeviceInfo.parse(self.send_cmd(COMMAND.DEVICE_INFO))

    def get_device_pubkey(self):
        pk_sd = self.send_cmd(COMMAND.GET_DEVICE_PUBKEY)
        return EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + pk_sd[1 : 1 + 64])

    def create_asym_session(self, auth_key_id, shsss):
        return AuthSession.create_asym_session(self, auth_key_id, shsss)

    def create_session(self, auth_key_id, key_enc, key_mac):
        """Creates an authenticated session with the YubiHSM.

        See also create_session_derived, which derives K-ENC and K-MAC from a
        password.

        :param int auth_key_id: The ID of the Authentication key used to
            authenticate the session.
        :param bytes key_enc: Static K-ENC used to establish session.
        :param bytes key_mac: Static K-MAC used to establish session.
        :return: An authenticated session.
        :rtype: AuthSession
        """
        return AuthSession.create_session(self, auth_key_id, key_enc, key_mac)

    def create_session_derived(self, auth_key_id, password):
        """Creates an authenticated session with the YubiHSM.

        Uses a supplied password to derive the keys K-ENC and K-MAC.

        :param int auth_key_id: The ID of the Authentication key used to
            authenticate the session.
        :param str password: The password used to derive the keys from.
        :return: An authenticated session.
        :rtype: AuthSession
        """
        key_enc, key_mac = utils.password_to_key(password)
        return self.create_session(auth_key_id, key_enc, key_mac)

    @classmethod
    def connect(cls, url=None):
        """Return a YubiHsm connected to the backend specified by the URL.

        If no URL is given this will attempt to connect to a YubiHSM connector
        running on localhost, using the default port.

        :param str url: (optional) A http(s):// or yhusb:// backend URL.
        :return: A YubiHsm instance connected to the backend referenced by the
            url.
        :rtype: YubiHsm
        """
        return cls(get_backend(url))

    def __repr__(self):
        return "{0.__class__.__name__}({0._backend})".format(self)


class _UnknownIntEnum(int):
    name = "UNKNOWN"

    def __repr__(self):
        return "<%s: %d>" % (self.name, self)

    def __str__(self):
        return self.name

    @property
    def value(self):
        return int(self)


class _UnknownAlgorithm(_UnknownIntEnum):
    """Wrapper for unknown ALGORITHM values.

    Provides obj.name, obj.value and and string representations."""

    name = "ALGORITHM.UNKNOWN"


def _algorithm(val):
    try:
        return ALGORITHM(val)
    except ValueError:
        return _UnknownAlgorithm(val)


class _UnknownCommand(_UnknownIntEnum):
    """Wrapper for unknown COMMAND values.

    Provides obj.name, obj.value and and string representations."""

    name = "COMMAND.UNKNOWN"


class DeviceInfo(
    namedtuple(
        "DeviceInfo",
        ["version", "serial", "log_size", "log_used", "supported_algorithms"],
    )
):
    """Data class holding various information about the YubiHSM.

    :param version: YubiHSM version tuple.
    :type version: tuple[int, int, int]
    :param int serial: YubiHSM serial number.
    :param int log_size: Log entry storage capacity.
    :param int log_used: Log entries currently stored.
    :param set[ALGORITHM] supported_algorithms: List of supported algorithms.
    """

    __slots__ = ()
    FORMAT = "!BBBIBB"
    LENGTH = struct.calcsize(FORMAT)

    @classmethod
    def parse(cls, data):
        """Parse a DeviceInfo from its binary representation.

        :param bytes data: Binary data to unpack from.
        :return: The parsed object.
        :rtype: DeviceInfo
        """
        unpacked = struct.unpack_from(cls.FORMAT, data)
        version = unpacked[:3]
        serial, log_size, log_used = unpacked[3:]
        algorithms = {_algorithm(a) for a in six.iterbytes(data[cls.LENGTH :])}

        return cls(version, serial, log_size, log_used, algorithms)


def _calculate_iv(key, counter):
    encryptor = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    ).encryptor()
    return encryptor.update(int_to_bytes(counter, 16)) + encryptor.finalize()


def _calculate_mac(key, chain, message):
    c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
    c.update(chain)
    c.update(message)
    chain = c.finalize()
    return chain, chain[:8]


class AuthSession(object):
    """An authenticated secure session with a YubiHSM.

    Typically you get an instance of this class by calling
    :func:`~YubiHsm.create_session` or :func:`~YubiHsm.create_session_derived`.
    """

    @classmethod
    def create_asym_session(cls, hsm, auth_key_id, shsss):

        esk_oce = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        epk_oce = esk_oce.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

        data = hsm.send_cmd(
            COMMAND.CREATE_SESSION, struct.pack("!H", auth_key_id) + epk_oce
        )

        sid = six.indexbytes(data, 0)
        epk_sd = data[1 : 1 + 65]
        receipt = data[1 + 65 : 1 + 65 + 16]

        shsee = esk_oce.exchange(
            ec.ECDH(),
            EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk_sd),
        )
        shs_oce = x963_kdf(hashes.SHA256(), shsee, shsss, 4 * 16)

        key_receipt = shs_oce[0:16]
        key_enc = shs_oce[16:32]
        key_mac = shs_oce[32:48]
        key_rmac = shs_oce[48:64]

        c = cmac.CMAC(algorithms.AES(key_receipt), backend=default_backend())
        c.update(epk_sd)
        c.update(epk_oce)
        receipt_oce = c.finalize()

        if not constant_time.bytes_eq(receipt_oce, receipt):
            raise YubiHsmAuthenticationError()

        return cls(hsm, sid, key_enc, key_mac, key_rmac, receipt)

    @classmethod
    def create_session(cls, hsm, auth_key_id, enc_key, mac_key):
        """Constructs an authenticated session.

        :param YubiHsm hsm: The YubiHSM connection.
        :param int auth_key_id: The ID of the Authentication key used to
            authenticate the session.
        :param bytes key_enc: Static `K-ENC` used to establish the session.
        :param bytes key_mac: Static `K-MAC` used to establish the session.
        """

        context = os.urandom(8)

        data = hsm.send_cmd(
            COMMAND.CREATE_SESSION, struct.pack("!H", auth_key_id) + context
        )

        sid = six.indexbytes(data, 0)
        context += data[1 : 1 + 8]
        card_crypto = data[9 : 9 + 8]

        key_enc = _derive(enc_key, KEY_ENC, context)
        key_mac = _derive(mac_key, KEY_MAC, context)
        key_rmac = _derive(mac_key, KEY_RMAC, context)
        gen_card_crypto = _derive(key_mac, CARD_CRYPTOGRAM, context, 0x40)

        if not constant_time.bytes_eq(gen_card_crypto, card_crypto):
            raise YubiHsmAuthenticationError()

        msg = struct.pack("!BHB", COMMAND.AUTHENTICATE_SESSION, 1 + 8 + 8, sid)
        msg += _derive(key_mac, HOST_CRYPTOGRAM, context, 0x40)
        mac_chain, mac = _calculate_mac(key_mac, b"\0" * 16, msg)
        msg += mac
        if _unpad_resp(hsm._transceive(msg), COMMAND.AUTHENTICATE_SESSION) != b"":
            raise YubiHsmInvalidResponseError("Non-empty response")
        return cls(hsm, sid, key_enc, key_mac, key_rmac, mac_chain)

    def __init__(self, hsm, sid, key_enc, key_mac, key_rmac, mac_chain):
        self._hsm = hsm
        self._sid = sid
        self._key_enc = key_enc
        self._key_mac = key_mac
        self._key_rmac = key_rmac
        self._mac_chain = mac_chain
        self._ctr = 1

    def close(self):
        """Close this session with the YubiHSM.

        Once closed, this session object can no longer be used, unless re-connected.
        """

        if self._sid is not None:
            try:
                self.send_secure_cmd(COMMAND.CLOSE_SESSION)
            finally:
                self._sid = None
                self._key_enc = self._key_mac = self._key_rmac = None

    def __enter__(self):
        return self

    def __exit__(self, typ, value, traceback):
        self.close()

    def _secure_transceive(self, msg):
        msg += b"\x80"
        padlen = 16 - len(msg) % 16
        msg = msg.ljust(len(msg) + padlen, b"\0")

        wrapped = struct.pack(
            "!BHB", COMMAND.SESSION_MESSAGE, 1 + len(msg) + 8, self.sid
        )
        cipher = Cipher(
            algorithms.AES(self._key_enc),
            modes.CBC(_calculate_iv(self._key_enc, self._ctr)),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        wrapped += encryptor.update(msg) + encryptor.finalize()
        next_mac_chain, mac = _calculate_mac(self._key_mac, self._mac_chain, wrapped)
        wrapped += mac
        raw_resp = self._hsm._transceive(wrapped)

        data = _unpad_resp(raw_resp, COMMAND.SESSION_MESSAGE)

        if six.indexbytes(data, 0) != self._sid:
            raise YubiHsmInvalidResponseError("Incorrect SID")

        rmac = _calculate_mac(self._key_rmac, next_mac_chain, raw_resp[:-8])[1]
        if not constant_time.bytes_eq(raw_resp[-8:], rmac):
            raise YubiHsmInvalidResponseError("Incorrect MAC")

        self._ctr += 1
        self._mac_chain = next_mac_chain

        decryptor = cipher.decryptor()
        return decryptor.update(data[1:-8]) + decryptor.finalize()

    @property
    def sid(self):
        """Session ID

        :return: The ID of the session.
        :rtype: int
        """
        return self._sid

    def send_secure_cmd(self, cmd, data=b""):
        """Send a command over the encrypted session.

        :param COMMAND cmd: The command to send.
        :param bytes data: The command payload to send.
        :return: The decrypted response data from the YubiHSM.
        :rtype: bytes
        """
        msg = struct.pack("!BH", cmd, len(data)) + data
        return _unpad_resp(self._secure_transceive(msg), cmd)

    def list_objects(
        self,
        object_id=None,
        object_type=None,
        domains=None,
        capabilities=None,
        algorithm=None,
        label=None,
    ):
        """List objects from the YubiHSM.

        This returns a list of all objects currently stored on the YubiHSM,
        which are accessible by this session. The arguments to this method can
        be used to filter the results returned.

        :param int object_id: (optional) Return only objects with this ID.
        :param OBJECT object_type: (optional) Return only objects of this type.
        :param int domains: (optional) Return only objects belonging to one or
            more of these domains.
        :param int capabilities: (optional) Return only objects with one or more
            of these capabilities.
        :param ALGORITHM algorithm: (optional) Return only objects with this
            algorithm.
        :param label: (optional) Return only objects with this label.
        :return: A list of matched objects.
        :rtype: list
        """
        msg = b""
        if object_id is not None:
            msg += struct.pack("!BH", LIST_FILTER.ID, object_id)
        if object_type is not None:
            msg += struct.pack("!BB", LIST_FILTER.TYPE, object_type)
        if domains is not None:
            msg += struct.pack("!BH", LIST_FILTER.DOMAINS, domains)
        if capabilities is not None:
            msg += struct.pack("!BQ", LIST_FILTER.CAPABILITIES, capabilities)
        if algorithm is not None:
            msg += struct.pack("!BB", LIST_FILTER.ALGORITHM, algorithm)
        if label is not None:
            msg += struct.pack(
                "!B%ds" % LABEL_LENGTH, LIST_FILTER.LABEL, _label_pack(label)
            )

        resp = self.send_secure_cmd(COMMAND.LIST_OBJECTS, msg)

        objects = []
        for i in range(0, len(resp), 4):
            object_id, typ, seq = struct.unpack("!HBB", resp[i : i + 4])
            objects.append(YhsmObject._create(typ, self, object_id, seq))
        return objects

    def get_object(self, object_id, object_type):
        """Get a reference to a YhsmObject with the given id and type.

        The object returned will be a subclass of YhsmObject corresponding to
        the given object_type.

        :param int object_id: The ID of the object to retrieve.
        :param OBJECT object_type: The type of the object to retrieve.
        :return: An object reference.
        :rtype: YhsmObject
        """
        return YhsmObject._create(object_type, self, object_id)

    def get_pseudo_random(self, length):
        """Get bytes from YubiHSM PRNG.

        :param int length: The number of bytes to return.
        :return: The requested number of random bytes.
        :rtype: bytes
        """
        msg = struct.pack("!H", length)
        return self.send_secure_cmd(COMMAND.GET_PSEUDO_RANDOM, msg)

    def reset_device(self):
        """Performs a factory reset of the YubiHSM.

        Resets and reboots the YubiHSM, deletes all Objects and restores the
        default Authkey.
        """
        try:
            if self.send_secure_cmd(COMMAND.RESET_DEVICE) != b"":
                raise YubiHsmInvalidResponseError("Non-empty response")
        except YubiHsmConnectionError:
            pass  # Assume reset went well, it may interrupt the connection.
        self._sid = None
        self._key_enc = self._key_mac = self._key_rmac = None
        self._hsm.close()

    def get_log_entries(self, previous_entry=None):
        """Get logs from the YubiHSM.

        This returns a tuple of the number of unlogged boot events, the number
        of unlogged authentication events, and the log entries from the YubiHSM.
        The chain of entry digests will be validated, starting from the first
        entry returned, or the one supplied as previous_entry.

        :param LogEntry previous_entry: (optional) Entry to start verification
            against.
        :return: A tuple consisting of the number of unlogged boot and
            authentication events, and the list of log entries.
        :rtype: LogData
        """
        resp = self.send_secure_cmd(COMMAND.GET_LOG_ENTRIES)
        boot, auth, num = struct.unpack("!HHB", resp[:5])

        data = resp[5:]
        if len(data) != num * LogEntry.LENGTH:
            raise YubiHsmInvalidResponseError("Incorrect length")

        logs = []
        for i in range(0, len(data), LogEntry.LENGTH):
            entry = LogEntry.parse(data[i : i + LogEntry.LENGTH])
            if previous_entry:
                if not entry.validate(previous_entry):
                    raise YubiHsmInvalidResponseError("Incorrect log digest")
            logs.append(entry)
            previous_entry = entry

        return LogData(boot, auth, logs)

    def set_log_index(self, index):
        """Clears logs to free up space for use with forced audit.

        :param int index: The log entry index to clear up to (inclusive).
        """
        msg = struct.pack("!H", index)
        if self.send_secure_cmd(COMMAND.SET_LOG_INDEX, msg) != b"":
            raise YubiHsmInvalidResponseError("Non-empty response")

    def put_option(self, option, value):
        """Set the raw value of a YubiHSM device option.

        :param OPTION option: The OPTION to set.
        :param bytes value: The value to set the OPTION to.
        """
        msg = struct.pack("!BH", option, len(value)) + value
        if self.send_secure_cmd(COMMAND.SET_OPTION, msg) != b"":
            raise YubiHsmInvalidResponseError("Non-empty response")

    def get_option(self, option):
        """Get the raw value of a YubiHSM device option.

        :param OPTION option: The OPTION to get.
        :return: The currently set value for the given OPTION
        :rtype: bytes
        """
        msg = struct.pack("!B", option)
        return self.send_secure_cmd(COMMAND.GET_OPTION, msg)

    def set_force_audit(self, audit):
        """Set the FORCE_AUDIT mode of the YubiHSM.

        :param AUDIT audit: The AUDIT mode to set.
        """
        self.put_option(OPTION.FORCE_AUDIT, struct.pack("B", audit))

    def get_force_audit(self):
        """Get the current setting for forced audit mode.

        :return: The AUDIT setting for FORCE_AUDIT.
        :rtype: AUDIT
        """
        return AUDIT(six.indexbytes(self.get_option(OPTION.FORCE_AUDIT), 0))

    def set_command_audit(self, commands):
        """Set audit mode of commands.

        Takes a dict of COMMAND -> AUDIT pairs and updates the audit settings
        for the commands given.

        :param commands: Settings to update.
        :type commands: dict[COMMAND, AUDIT]

        :Example:

        >>> session.set_comment_audit({
        ...     COMMAND.ECHO: AUDIT.OFF,
        ...     COMMAND.LIST_OBJECTS: AUDIT.ON
        ... })
        """
        msg = b"".join(struct.pack("!BB", k, v) for (k, v) in commands.items())
        self.put_option(OPTION.COMMAND_AUDIT, msg)

    def get_command_audit(self):
        """Get a mapping of all available commands and their audit settings.

        :return: Dictionary of COMMAND -> AUDIT pairs.
        :rtype: dict[COMMAND, AUDIT]
        """
        resp = self.get_option(OPTION.COMMAND_AUDIT)
        ret = {}
        for i in range(0, len(resp), 2):
            cmd = six.indexbytes(resp, i)
            val = AUDIT(six.indexbytes(resp, i + 1))
            try:
                ret[COMMAND(cmd)] = val
            except ValueError:
                ret[_UnknownCommand(cmd)] = val
        return ret

    def __repr__(self):
        return "{0.__class__.__name__}(id={0._sid}, hsm={0._hsm})".format(self)


class LogData(namedtuple("LogData", ["n_boot", "n_auth", "entries"])):
    """Data class holding response data from a GET_LOGS command.

    :param int n_boot: Number of unlogged boot events.
    :param int n_auth: Number of unlogged authentication events.
    :param list[LogEntry] entries: List of LogEntry items.
    """

    __slots__ = ()


class LogEntry(
    namedtuple(
        "LogEntry",
        [
            "number",
            "command",
            "length",
            "session_key",
            "target_key",
            "second_key",
            "result",
            "tick",
            "digest",
        ],
    )
):
    """YubiHSM log entry.

    :param int number: The sequence number of the entry.
    :param int command: The COMMAND executed.
    :param int length: The length of the command.
    :param int session_key: The ID of the Authentication Key for the session.
    :param int target_key: The ID of the key used by the command.
    :param int second_key: The ID of the secondary key used by the command, if
        applicable.
    :param int result: The result byte of the response.
    :param int tick: The YubiHSM system tick value when the command was run.
    :param bytes digest: A truncated hash of the entry and previous digest.
    """

    __slots__ = ()
    FORMAT = "!HBHHHHBL16s"
    LENGTH = struct.calcsize(FORMAT)

    @property
    def data(self):
        """Get log entry binary data.

        :return: The binary LogEntry data, excluding the digest.
        :rtype: bytes
        """
        return struct.pack(self.FORMAT, *self)[:-16]

    @classmethod
    def parse(cls, data):
        """Parse a LogEntry from its binary representation.

        :param bytes data: Binary data to unpack from.
        :return: The parsed object.
        :rtype: LogEntry
        """
        return cls(*struct.unpack(cls.FORMAT, data))

    def validate(self, previous_entry):
        """Validate the hash of a single log entry.

        Validates the hash of this entry with regard to the previous entry's
        hash. The previous entry is the LogEntry with the previous number,
        previous_entry.number == self.number - 1

        :param LogEntry previous_entry: The previous log entry to validate
            against.
        :return: True if the digest is correct, False if not.
        :rtype: bool
        """

        if (self.number - previous_entry.number) & 0xFFFF != 1:
            raise ValueError("previous_entry has wrong number!")

        digest = sha256(self.data + previous_entry.digest).digest()[:16]
        return constant_time.bytes_eq(self.digest, digest)
