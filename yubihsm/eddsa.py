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

"""Functions for serializing and deserializing Ed25519 keys."""


# We expect cryptography to support Ed25519 in the near future and will replace
# these classes once it does, while allowing for the two functions to remain
# if needed.


class _Ed25519PrivateKey(object):
    def __init__(self, private_bytes):
        self._private_bytes = private_bytes


class _Ed25519PublicKey(object):
    def __init__(self, public_bytes):
        self._public_bytes = public_bytes


def load_ed25519_private_key(seed):
    """Load an Ed25519 key from a private seed (32 bytes).

    :param bytes seed: A 32 byte seed.
    :return: An Ed25519 private key object.
    """
    return _Ed25519PrivateKey(seed)


def serialize_ed25519_public_key(key):
    """Serialize an Ed25519 public key object to bytes.

    :param Ed25519 key: The public key to serialze.
    :return: The 32 byte binary representation of a public Ed25519 key.
    :rtype: bytes
    """
    return key._public_bytes
