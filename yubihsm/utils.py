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

"""Various utility functions used throughout the library."""


from __future__ import absolute_import, division

import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from binascii import b2a_hex


def int_from_bytes(value, byteorder="big"):
    if byteorder != "big":
        raise ValueError("byteorder must be big")
    return int(b2a_hex(value), 16)


def password_to_key(password):
    """Derive keys for establishing a YubiHSM session from a password.

    :return: A tuple containing the encryption key, and MAC key.
    :rtype: tuple[bytes, bytes]
    """
    if isinstance(password, six.text_type):
        password = password.encode("utf8")
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"Yubico",
        iterations=10000,
        backend=default_backend(),
    ).derive(password)
    key_enc, key_mac = key[:16], key[16:]
    return key_enc, key_mac
