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

"""Classes for interacting with objects on a YubiHSM."""


from __future__ import absolute_import, division

from . import utils
from .defs import ALGORITHM, COMMAND, OBJECT, ORIGIN
from .exceptions import YubiHsmInvalidResponseError
from .eddsa import (
    _is_ed25519_private_key,
    _serialize_ed25519_private_key,
    _deserialize_ed25519_public_key,
)

from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.utils import int_to_bytes, int_from_bytes
from collections import namedtuple
import six
import copy
import struct


LABEL_LENGTH = 40


def _label_pack(label):
    """Pack a label into binary form."""
    if isinstance(label, six.text_type):
        label = label.encode("utf8")
    if len(label) > LABEL_LENGTH:
        raise ValueError("Label must be no longer than %d bytes" % LABEL_LENGTH)
    return label


def _label_unpack(packed):
    """Unpack a label from its binary form."""
    try:
        return packed.split(b"\0", 2)[0].decode("utf8")
    except UnicodeDecodeError:
        # Not valid UTF-8 string, return the raw data.
        return packed


class ObjectInfo(
    namedtuple(
        "ObjectInfo",
        [
            "capabilities",
            "id",
            "size",
            "domains",
            "object_type",
            "algorithm",
            "sequence",
            "origin",
            "label",
            "delegated_capabilities",
        ],
    )
):
    """Data structure holding various information about an object.

    :param int capabilities: The capabilities of the object.
    :param int id: The ID of the object.
    :param int size: The size of the object.
    :param int domains: The set of domains the object belongs to.
    :param OBJECT object_type: The type of the object.
    :param ALGORITHM algorithm: The algorithm of the object.
    :param int sequence: The sequence number of the object.
    :param ORIGIN origin: How the object was created/imported.
    :param label: The label of the object.
    :type label: str or bytes
    :param int delegated_capabilities: The set of delegated capabilities for the
        object.
    """

    __slots__ = ()
    FORMAT = "!QHHHBBBB%dsQ" % LABEL_LENGTH
    LENGTH = struct.calcsize(FORMAT)

    @classmethod
    def parse(cls, data):
        """Parse an ObjectInfo from its binary representation."""
        tmp = cls(*struct.unpack(cls.FORMAT, data))
        return tmp._replace(
            object_type=OBJECT(tmp.object_type),
            algorithm=ALGORITHM(tmp.algorithm),
            origin=ORIGIN(tmp.origin),
            label=_label_unpack(tmp.label),
        )


class YhsmObject(object):
    """A reference to an object stored in a YubiHSM.

    YubiHSM objects are uniquely identified by their type and ID combined.

    :param OBJECT object_type: The type of the object.
    :param int id: The ID of the object.
    :param AuthSession session: The session to use for YubiHSM communication.
    """

    object_type = None

    def __init__(self, session, object_id, seq=None):
        self.session = session
        self.id = object_id
        self._seq = seq

    def with_session(self, session):
        """Get a copy of the object reference, using the given session.

        :param AuthSession session: The session to use for the created reference.
        :return: A new reference to the object, associated wth the given session.
        :rtype: YhsmObject
        """
        other = copy.copy(self)
        other.session = session
        return other

    def get_info(self):
        """Read extended information about the object from the YubiHSM.

        :return: Information about the object.
        :rtype: ObjectInfo
        """
        msg = struct.pack("!HB", self.id, self.object_type)
        resp = self.session.send_secure_cmd(COMMAND.GET_OBJECT_INFO, msg)
        try:
            return ObjectInfo.parse(resp)
        except ValueError:
            raise YubiHsmInvalidResponseError()

    def delete(self):
        """Deletes the object from the YubiHSM.

        .. warning:: This action in irreversible.
        """
        msg = struct.pack("!HB", self.id, self.object_type)
        if self.session.send_secure_cmd(COMMAND.DELETE_OBJECT, msg) != b"":
            raise YubiHsmInvalidResponseError()

    @staticmethod
    def _create(object_type, session, object_id, seq=None):
        """
        Creates instance of `object_type`.

        When object type is not recognized, _create constructs an
        instance of `_UnknownYhsmObject`.
        """
        for cls in YhsmObject.__subclasses__():
            if cls.object_type == object_type:
                return cls(session, object_id, seq)
        return _UnknownYhsmObject(object_type, session, object_id, seq)

    @classmethod
    def _from_command(cls, session, cmd, data):
        ret = session.send_secure_cmd(cmd, data)
        return cls(session, struct.unpack("!H", ret)[0])

    def __repr__(self):
        return "{0.__class__.__name__}(id={0.id})".format(self)


class _UnknownYhsmObject(YhsmObject):
    """
    _UnknownYhsmObject is a generic YhsmObject with `self.object_type`
    set to the specified `object_type` parameter.
    """

    def __init__(self, object_type, *args, **kwargs):
        super(_UnknownYhsmObject, self).__init__(*args, **kwargs)
        self.object_type = object_type


class Opaque(YhsmObject):
    """Object used to store arbitrary data on the YubiHSM.

    Supported algorithms:
        - :class:`~yubihsm.defs.ALGORITHM.OPAQUE_DATA`
        - :class:`~yubihsm.defs.ALGORITHM.OPAQUE_X509_CERTIFICATE`
    """

    object_type = OBJECT.OPAQUE

    @classmethod
    def put(cls, session, object_id, label, domains, capabilities, algorithm, data):
        """Import an Opaque object into the YubiHSM.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param ALGORITHM algorithm: The algorithm to use for the object.
        :param bytes data: The binary data to store.
        :return: A reference to the newly created object.
        :rtype: Opaque
        """
        if not data:
            raise ValueError("Cannot store empty data")
        msg = struct.pack(
            "!H%dsHQB" % LABEL_LENGTH,
            object_id,
            _label_pack(label),
            domains,
            capabilities,
            algorithm,
        )
        msg += data
        return cls._from_command(session, COMMAND.PUT_OPAQUE, msg)

    def get(self):
        """Read the data of an Opaque object from the YubiHSM.

        :return: The data stored for the object.
        :rtype: bytes
        """
        msg = struct.pack("!H", self.id)
        return self.session.send_secure_cmd(COMMAND.GET_OPAQUE, msg)

    @classmethod
    def put_certificate(
        cls, session, object_id, label, domains, capabilities, certificate
    ):
        """Import an X509 certificate into the YubiHSM as an Opaque.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param cryptography.x509.Certificate certificate: A certificate to
            import.
        :return: A reference to the newly created object.
        :rtype: Opaque
        """
        encoded_cert = certificate.public_bytes(Encoding.DER)
        return cls.put(
            session,
            object_id,
            label,
            domains,
            capabilities,
            ALGORITHM.OPAQUE_X509_CERTIFICATE,
            encoded_cert,
        )

    def get_certificate(self):
        """Read an Opaque object from the YubiHSM, parsed as a certificate.

        :return: The certificate stored for the object.
        :rtype: cryptography.x509.Certificate
        """
        return x509.load_der_x509_certificate(self.get(), default_backend())


class AuthenticationKey(YhsmObject):
    """Used to authenticate a session with the YubiHSM.

    AuthenticationKeys use two separate keys to mutually authenticate and set up
    a secure session with a YubiHSM. These two keys can either be given
    explicitly, or be derived from a password.
    """

    object_type = OBJECT.AUTHENTICATION_KEY

    @classmethod
    def put_derived(
        cls,
        session,
        object_id,
        label,
        domains,
        capabilities,
        delegated_capabilities,
        password,
    ):
        """Create an AuthenticationKey derived from a password.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param int delegated_capabilities: The set of capabilities that the
            AuthenticationKey can give to objects created when authenticated
            using it.
        :param str password: The password to derive raw keys from.
        :return: A reference to the newly created object.
        :rtype: AuthenticationKey
        """
        key_enc, key_mac = utils.password_to_key(password)
        return cls.put(
            session,
            object_id,
            label,
            domains,
            capabilities,
            delegated_capabilities,
            key_enc,
            key_mac,
        )

    @classmethod
    def put(
        cls,
        session,
        object_id,
        label,
        domains,
        capabilities,
        delegated_capabilities,
        key_enc,
        key_mac,
    ):
        """Create an AuthenticationKey by providing raw keys.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param int delegated_capabilities: The set of capabilities that the
            AuthenticationKey can give to objects created when authenticated
            using it.
        :param bytes key_enc: The raw encryption key.
        :param bytes key_mac: The raw MAC key.
        :return: A reference to the newly created object.
        :rtype: AuthenticationKey
        """
        msg = struct.pack(
            "!H%dsHQBQ" % LABEL_LENGTH,
            object_id,
            _label_pack(label),
            domains,
            capabilities,
            ALGORITHM.AES128_YUBICO_AUTHENTICATION,
            delegated_capabilities,
        )
        msg += key_enc + key_mac
        return cls._from_command(session, COMMAND.PUT_AUTHENTICATION_KEY, msg)

    @classmethod
    def put_asym(
        cls,
        session,
        object_id,
        label,
        domains,
        capabilities,
        delegated_capabilities,
        pk_oce,
    ):
        """Create an AuthenticationKey by providing raw public key.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param int delegated_capabilities: The set of capabilities that the
            AuthenticationKey can give to objects created when authenticated
            using it.
        :param bytes pk_oce: The raw public key.
        :return: A reference to the newly created object.
        :rtype: AuthenticationKey
        """
        msg = struct.pack(
            "!H%dsHQBQ" % LABEL_LENGTH,
            object_id,
            _label_pack(label),
            domains,
            capabilities,
            ALGORITHM.EC_P256_YUBICO_AUTHENTICATION,
            delegated_capabilities,
        )
        msg += pk_oce
        return cls._from_command(session, COMMAND.PUT_AUTHENTICATION_KEY, msg)

    def change_password(self, password):
        """Change the password used to authenticate a session.

        Changes the raw keys used for authentication, by deriving them from a
        password.

        :param str password: The password to derive raw keys from.
        """
        key_enc, key_mac = utils.password_to_key(password)
        self.change_key(key_enc, key_mac)

    def change_key(self, key_enc, key_mac):
        """Change the raw keys used to authenticate a session.

        :param bytes key_enc: The raw encryption key.
        :param bytes key_mac: The raw MAC key.
        """
        msg = (
            struct.pack("!HB", self.id, ALGORITHM.AES128_YUBICO_AUTHENTICATION)
            + key_enc
            + key_mac
        )
        resp = self.session.send_secure_cmd(COMMAND.CHANGE_AUTHENTICATION_KEY, msg)
        if struct.unpack("!H", resp)[0] != self.id:
            raise YubiHsmInvalidResponseError("Wrong ID returned")

    def change_asym_key(self, key):
        """Change the raw keys used to authenticate a session.

        :param bytes key_enc: The raw encryption key.
        :param bytes key_mac: The raw MAC key.
        """
        msg = struct.pack("!HB", self.id, ALGORITHM.EC_P256_YUBICO_AUTHENTICATION) + key
        resp = self.session.send_secure_cmd(COMMAND.CHANGE_AUTHENTICATION_KEY, msg)
        if struct.unpack("!H", resp)[0] != self.id:
            raise YubiHsmInvalidResponseError("Wrong ID returned")


class AsymmetricKey(YhsmObject):
    """Used to sign/decrypt data with the private key of an asymmetric key pair.

    Supported algorithms:
        - :class:`~yubihsm.defs.ALGORITHM.RSA_2048`
        - :class:`~yubihsm.defs.ALGORITHM.RSA_3072`
        - :class:`~yubihsm.defs.ALGORITHM.RSA_4096`
        - :class:`~yubihsm.defs.ALGORITHM.EC_P224`
        - :class:`~yubihsm.defs.ALGORITHM.EC_P256`
        - :class:`~yubihsm.defs.ALGORITHM.EC_P384`
        - :class:`~yubihsm.defs.ALGORITHM.EC_P521`
        - :class:`~yubihsm.defs.ALGORITHM.EC_K256`
        - :class:`~yubihsm.defs.ALGORITHM.EC_BP256`
        - :class:`~yubihsm.defs.ALGORITHM.EC_BP384`
        - :class:`~yubihsm.defs.ALGORITHM.EC_BP512`
        - :class:`~yubihsm.defs.ALGORITHM.EC_ED25519`
    """

    object_type = OBJECT.ASYMMETRIC_KEY

    @classmethod
    def put(cls, session, object_id, label, domains, capabilities, key):
        """Import a private key into the YubiHSM.

        RSA and EC keys can be created by using the cryptography APIs. You can
        then pass either a
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
        or a
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
        as `key`.

        EdDSA keys can be created using the Cryptography APIs if available, or
        by calling
        :func:`~yubihsm.eddsa.load_ed25519_private_key`.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param key: The private key to import.
        :return: A reference to the newly created object.
        :rtype: AsymmetricKey
        """
        if isinstance(key, rsa.RSAPrivateKey):
            numbers = key.private_numbers()
            serialized = int_to_bytes(numbers.p) + int_to_bytes(numbers.q)
            algo = getattr(ALGORITHM, "RSA_%d" % key.key_size)
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            numbers = key.private_numbers()
            serialized = int_to_bytes(
                numbers.private_value, (key.curve.key_size + 7) // 8
            )
            algo = ALGORITHM.for_curve(key.curve)
        elif _is_ed25519_private_key(key):
            serialized = _serialize_ed25519_private_key(key)
            algo = ALGORITHM.EC_ED25519
        else:
            raise ValueError("Unsupported key")

        msg = (
            struct.pack(
                "!H%dsHQB" % LABEL_LENGTH,
                object_id,
                _label_pack(label),
                domains,
                capabilities,
                algo,
            )
            + serialized
        )
        return cls._from_command(session, COMMAND.PUT_ASYMMETRIC_KEY, msg)

    @classmethod
    def generate(cls, session, object_id, label, domains, capabilities, algorithm):
        """Generate a new private key in the YubiHSM.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param ALGORITHM algorithm: The algorithm to use for the private key.
        :return: A reference to the newly created object.
        :rtype: AsymmetricKey
        """
        msg = struct.pack(
            "!H%dsHQB" % LABEL_LENGTH,
            object_id,
            _label_pack(label),
            domains,
            capabilities,
            algorithm,
        )
        return cls._from_command(session, COMMAND.GENERATE_ASYMMETRIC_KEY, msg)

    def get_public_key(self):
        """Get the public key of the key pair.

        This will return either a
        :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`
        or a
        :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
        depending on the algorithm of the key.

        Ed25519 keys will be returned as a Cryptography
        :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`
        object if possible (requires Cryptography 2.6 or later), or an internal
        representation if not, either which can be serialized using the
        :func:`~yubihsm.eddsa.serialize_ed25519_public_key` function.

        :return: The public key of the key pair.
        """
        msg = struct.pack("!H", self.id)
        ret = self.session.send_secure_cmd(COMMAND.GET_PUBLIC_KEY, msg)
        algo = ALGORITHM(six.indexbytes(ret, 0))
        raw_key = ret[1:]
        if algo in [ALGORITHM.RSA_2048, ALGORITHM.RSA_3072, ALGORITHM.RSA_4096]:
            num = int_from_bytes(raw_key, "big")
            pubkey = rsa.RSAPublicNumbers(e=0x10001, n=num)
        elif algo in [
            ALGORITHM.EC_P224,
            ALGORITHM.EC_P256,
            ALGORITHM.EC_P384,
            ALGORITHM.EC_P521,
            ALGORITHM.EC_K256,
            ALGORITHM.EC_BP256,
            ALGORITHM.EC_BP384,
            ALGORITHM.EC_BP512,
        ]:
            c_len = len(raw_key) // 2
            x = int_from_bytes(raw_key[:c_len], "big")
            y = int_from_bytes(raw_key[c_len:], "big")
            pubkey = ec.EllipticCurvePublicNumbers(curve=algo.to_curve(), x=x, y=y)
        elif algo in [ALGORITHM.EC_ED25519]:
            return _deserialize_ed25519_public_key(raw_key)

        return pubkey.public_key(backend=default_backend())

    def get_certificate(self):
        """Get the X509 certificate associated with the key.

        An X509 certificate is associated with an asymmetric key if it is stored
        as an Opaque object with the same object ID as the key, and it has the
        :class:`~yubihsm.defs.ALGORITHM.OPAQUE_X509_CERTIFICATE` algorithm set.

        Equivalent to calling `Opaque(session, key_id).get_certificate()`.

        :return: The certificate stored for the object.
        :rtype: cryptography.x509.Certificate
        """
        return Opaque(self.session, self.id).get_certificate()

    def put_certificate(self, label, domains, capabilities, certificate):
        """Store an X509 certificate associated with this key.

        Equivalent to calling `Opaque.put_certificate(session, key_id, ...)`.

        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param cryptography.x509.Certificate certificate: A certificate to
            import.
        :return: A reference to the newly created object.
        :rtype: Opaque
        """
        return Opaque.put_certificate(
            self.session, self.id, label, domains, capabilities, certificate
        )

    def sign_ecdsa(self, data, hash=hashes.SHA256(), length=0):
        """Sign data using ECDSA.

        :param bytes data: The data to sign.
        :param hash: (optional) The algorithm to use when hashing the data.
        :type hash: cryptography.hazmat.primitives.hashes.HashAlgorithm
        :param int length: (optional) length to pad/truncate the hash to.
        :return: The resulting signature.
        :rtype: bytes
        """
        digest = hashes.Hash(hash, backend=default_backend())
        digest.update(data)
        data = digest.finalize()

        if not length:
            length = hash.digest_size

        msg = struct.pack("!H%ds" % length, self.id, data.rjust(length, b"\0"))
        return self.session.send_secure_cmd(COMMAND.SIGN_ECDSA, msg)

    def derive_ecdh(self, public_key):
        """Perform an ECDH key exchange as specified in SP 800-56A.

        :param public_key: The public key to use for the key exchange.
        :type public_key:
            cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey
        :return: The resulting shared key.
        :rtype: bytes
        """
        try:
            point = public_key.public_bytes(
                Encoding.X962, PublicFormat.UncompressedPoint
            )
        except AttributeError:  # Cryptography <2.5
            point = public_key.public_numbers().encode_point()
        msg = struct.pack("!H", self.id) + point
        return self.session.send_secure_cmd(COMMAND.DERIVE_ECDH, msg)

    def sign_pkcs1v1_5(self, data, hash=hashes.SHA256()):
        """Sign data using RSASSA-PKCS1-v1_5.

        :param bytes data: The data to sign.
        :param hash: (optional) The algorithm to use when hashing the data.
        :type hash: cryptography.hazmat.primitives.hashes.HashAlgorithm
        :return: The resulting signature.
        :rtype: bytes
        """
        digest = hashes.Hash(hash, backend=default_backend())
        digest.update(data)

        data = digest.finalize()

        msg = struct.pack("!H", self.id) + data
        return self.session.send_secure_cmd(COMMAND.SIGN_PKCS1, msg)

    def decrypt_pkcs1v1_5(self, data):
        """Decrypt data encrypted with RSAES-PKCS1-v1_5.

        :param bytes data: The ciphertext to decrypt.
        :return: The decrypted plaintext.
        :rtype: bytes
        """
        msg = struct.pack("!H", self.id) + data
        return self.session.send_secure_cmd(COMMAND.DECRYPT_PKCS1, msg)

    def sign_pss(self, data, salt_len, hash=hashes.SHA256(), mgf_hash=hashes.SHA256()):
        """Sign data using RSASSA-PSS with MGF1.

        :param bytes data: The data to sign.
        :param int salt_len: The length of the salt to use.
        :param hash: (optional) The algorithm to use when hashing the data.
        :type hash: cryptography.hazmat.primitives.hashes.HashAlgorithm
        :param mgf_hash: (optional) The algorithm to use for MGF1.
        :type mgf_hash: cryptography.hazmat.primitives.hashes.HashAlgorithm
        :return: The resulting signature.
        :rtype: bytes
        """
        digest = hashes.Hash(hash, backend=default_backend())
        digest.update(data)
        data = digest.finalize()

        mgf = getattr(ALGORITHM, "RSA_MGF1_%s" % mgf_hash.name.upper())

        msg = struct.pack("!HBH", self.id, mgf, salt_len) + data
        return self.session.send_secure_cmd(COMMAND.SIGN_PSS, msg)

    def decrypt_oaep(
        self, data, label=b"", hash=hashes.SHA256(), mgf_hash=hashes.SHA256()
    ):
        """Decrypt data encrypted with RSAES-OAEP.

        :param bytes data: The ciphertext to decrypt.
        :param bytes label: (optional) OAEP label.
        :param hash: (optional) The algorithm to use when hashing the data.
        :type hash: cryptography.hazmat.primitives.hashes.HashAlgorithm
        :param mgf_hash: (optional) The algorithm to use for MGF1.
        :type mgf_hash: cryptography.hazmat.primitives.hashes.HashAlgorithm
        :return: The decrypted plaintext.
        :rtype: bytes
        """
        digest = hashes.Hash(hash, backend=default_backend())
        digest.update(label)

        mgf = getattr(ALGORITHM, "RSA_MGF1_%s" % mgf_hash.name.upper())

        msg = struct.pack("!HB", self.id, mgf) + data + digest.finalize()
        return self.session.send_secure_cmd(COMMAND.DECRYPT_OAEP, msg)

    def sign_eddsa(self, data):
        """Sign data using EdDSA.

        :param bytes data: The data to sign.
        :return: The resulting signature.
        :rtype: bytes
        """
        msg = struct.pack("!H", self.id) + data
        return self.session.send_secure_cmd(COMMAND.SIGN_EDDSA, msg)

    def attest(self, attesting_key_id=0):
        """Attest this asymmetric key.

        Creates an X509 certificate containing this key pair's public key,
        signed by the asymmetric key identified by the given ID.
        You also need a X509 certificate stored with the same ID as the
        attesting key in the YubiHSM, to be used as a template.

        :param int attesting_key_id: (optional) The ID of the asymmetric key
            used to attest. If omitted, the built-in Yubico attestation key is
            used.
        :return: The attestation certificate.
        :rtype: cryptography.x509.Certificate
        """
        msg = struct.pack("!HH", self.id, attesting_key_id)
        resp = self.session.send_secure_cmd(COMMAND.SIGN_ATTESTATION_CERTIFICATE, msg)
        return x509.load_der_x509_certificate(resp, default_backend())

    def sign_ssh_certificate(
        self, template_id, request, algorithm=ALGORITHM.RSA_PKCS1_SHA1
    ):
        """Sign an SSH certificate request.

        :param int template_id: The ID of the SSH TEMPLATE to use.
        :param bytes request: The SSH certificate request.
        :return: The signed SSH certificate.
        :rtype: bytes
        """
        msg = struct.pack("!HH", self.id, template_id) + request
        return self.session.send_secure_cmd(COMMAND.SIGN_SSH_CERTIFICATE, msg)


class WrapKey(YhsmObject):
    """Used to import and export other objects under wrap.

    Supported algorithms:
        - :class:`~yubihsm.defs.ALGORITHM.AES128_CCM_WRAP`
        - :class:`~yubihsm.defs.ALGORITHM.AES192_CCM_WRAP`
        - :class:`~yubihsm.defs.ALGORITHM.AES256_CCM_WRAP`
    """

    object_type = OBJECT.WRAP_KEY

    @classmethod
    def generate(
        cls,
        session,
        object_id,
        label,
        domains,
        capabilities,
        algorithm,
        delegated_capabilities,
    ):
        """Generate a new wrap key in the YubiHSM.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param ALGORITHM algorithm: The algorithm to use for the wrap key.
        :return: A reference to the newly created object.
        :rtype: WrapKey
        """
        msg = struct.pack(
            "!H%dsHQBQ" % LABEL_LENGTH,
            object_id,
            _label_pack(label),
            domains,
            capabilities,
            algorithm,
            delegated_capabilities,
        )
        return cls._from_command(session, COMMAND.GENERATE_WRAP_KEY, msg)

    @classmethod
    def put(
        cls,
        session,
        object_id,
        label,
        domains,
        capabilities,
        algorithm,
        delegated_capabilities,
        key,
    ):
        """Import a wrap key into the YubiHSM.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param ALGORITHM algorithm: The algorithm to use for the wrap key.
        :param int delegated_capabilities: The set of capabilities that the
            WrapKey can give to objects that it imports.
        :param bytes key: The raw encryption key corresponding to the algorithm.
        :return: A reference to the newly created object.
        :rtype: WrapKey
        """
        msg = struct.pack(
            "!H%dsHQBQ" % LABEL_LENGTH,
            object_id,
            _label_pack(label),
            domains,
            capabilities,
            algorithm,
            delegated_capabilities,
        )
        msg += key
        return cls._from_command(session, COMMAND.PUT_WRAP_KEY, msg)

    def wrap_data(self, data):
        """Wrap (encrypt) arbitrary data.

        :param bytes data: The data to encrypt.
        :return: The encrypted data.
        :rtype: bytes
        """
        msg = struct.pack("!H", self.id) + data
        return self.session.send_secure_cmd(COMMAND.WRAP_DATA, msg)

    def unwrap_data(self, data):
        """Unwrap (decrypt) arbitrary data.

        :param bytes data: The encrypted data to decrypt.
        :return: The decrypted data.
        :rtype: bytes
        """
        msg = struct.pack("!H", self.id) + data
        return self.session.send_secure_cmd(COMMAND.UNWRAP_DATA, msg)

    def export_wrapped(self, obj):
        """Exports an object under wrap.

        :param YhsmObject obj: The object to export.
        :return: The encrypted object data.
        :rtype: bytes
        """
        msg = struct.pack("!HBH", self.id, obj.object_type, obj.id)
        return self.session.send_secure_cmd(COMMAND.EXPORT_WRAPPED, msg)

    def import_wrapped(self, wrapped_obj):
        """Imports an object previously exported under wrap.

        :param bytes wraped_obj: The encrypted object data.
        :return: A reference to the imported object.
        :rtype: YhsmObject
        """
        msg = struct.pack("!H", self.id) + wrapped_obj
        ret = self.session.send_secure_cmd(COMMAND.IMPORT_WRAPPED, msg)
        object_type, object_id = struct.unpack("!BH", ret)
        return YhsmObject._create(object_type, self.session, object_id)


class HmacKey(YhsmObject):
    """Used to calculate and verify HMAC signatures.

    Supported algorithms:
        - :class:`~yubihsm.defs.ALGORITHM.HMAC_SHA1`
        - :class:`~yubihsm.defs.ALGORITHM.HMAC_SHA256`
        - :class:`~yubihsm.defs.ALGORITHM.HMAC_SHA384`
        - :class:`~yubihsm.defs.ALGORITHM.HMAC_SHA512`
    """

    object_type = OBJECT.HMAC_KEY

    @classmethod
    def generate(
        cls,
        session,
        object_id,
        label,
        domains,
        capabilities,
        algorithm=ALGORITHM.HMAC_SHA256,
    ):
        """Generate a new HMAC key in the YubiHSM.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param ALGORITHM algorithm: (optional) The algorithm to use for the HMAC
            key.
        :return: A reference to the newly created object.
        :rtype: HmacKey
        """
        msg = struct.pack(
            "!H%dsHQB" % LABEL_LENGTH,
            object_id,
            _label_pack(label),
            domains,
            capabilities,
            algorithm,
        )
        return cls._from_command(session, COMMAND.GENERATE_HMAC_KEY, msg)

    @classmethod
    def put(
        cls,
        session,
        object_id,
        label,
        domains,
        capabilities,
        key,
        algorithm=ALGORITHM.HMAC_SHA256,
    ):
        """Import an HMAC key into the YubiHSM.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param bytes key: The raw key corresponding to the algorithm.
        :param ALGORITHM algorithm: (optional) The algorithm to use for the HMAC
            key.
        :return: A reference to the newly created object.
        :rtype: HmacKey
        """
        msg = (
            struct.pack(
                "!H%dsHQB" % LABEL_LENGTH,
                object_id,
                _label_pack(label),
                domains,
                capabilities,
                algorithm,
            )
            + key
        )
        return cls._from_command(session, COMMAND.PUT_HMAC_KEY, msg)

    def sign_hmac(self, data):
        """Calculate the HMAC signature of the given data.

        :param bytes data: The data to sign.
        :return: The signature.
        :rtype: bytes
        """
        msg = struct.pack("!H", self.id) + data
        return self.session.send_secure_cmd(COMMAND.SIGN_HMAC, msg)

    def verify_hmac(self, signature, data):
        """
        Verify an HMAC signature.

        :param bytes signature: The signature to verify.
        :param bytes data: The data to verify the signature against.
        :return: True if verification succeeded, False if not.
        :rtype: bool
        """
        msg = struct.pack("!H", self.id) + signature + data
        return self.session.send_secure_cmd(COMMAND.VERIFY_HMAC, msg) == b"\1"


class Template(YhsmObject):
    """Binary template used to validate SSH certificate requests.

    Supported algorithms:
        - :class:`~yubihsm.defs.ALGORITHM.TEMPLATE_SSH`
    """

    object_type = OBJECT.TEMPLATE

    @classmethod
    def put(cls, session, object_id, label, domains, capabilities, algorithm, data):
        """Import a Template into the YubiHSM.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param ALGORITHM algorithm: The algorithm to use for the template.
        :param bytes data: The template data.
        :return: A reference to the newly created object.
        :rtype: Template
        """
        msg = struct.pack(
            "!H%dsHQB" % LABEL_LENGTH,
            object_id,
            _label_pack(label),
            domains,
            capabilities,
            algorithm,
        )
        msg += data
        return cls._from_command(session, COMMAND.PUT_TEMPLATE, msg)

    def get(self):
        """Read a Template from the YubiHSM.

        :return: The template data.
        :rtype: bytes
        """
        msg = struct.pack("!H", self.id)
        return self.session.send_secure_cmd(COMMAND.GET_TEMPLATE, msg)


class OtpData(
    namedtuple(
        "OtpData", ["use_counter", "session_counter", "timestamp_high", "timestamp_low"]
    )
):
    """Decrypted OTP counter values.

    :param int use_counter: 16 bit counter incremented on each power cycle.
    :param int session_counter: 8 bit counter incremented on each touch.
    :param int timestamp_high: 8 bit high part of the timestamp.
    :param int timestamp_low: 16 bit low part of the timestamp.
    """

    __slots__ = ()


class OtpAeadKey(YhsmObject):
    """Used to decrypt and use a Yubico OTP AEAD for OTP decryption.

    Supported algorithms:
        - :class:`~yubihsm.defs.ALGORITHM.AES128_YUBICO_OTP`
        - :class:`~yubihsm.defs.ALGORITHM.AES192_YUBICO_OTP`
        - :class:`~yubihsm.defs.ALGORITHM.AES256_YUBICO_OTP`
    """

    object_type = OBJECT.OTP_AEAD_KEY

    @classmethod
    def put(
        cls, session, object_id, label, domains, capabilities, algorithm, nonce_id, key
    ):
        """Import an OTP AEAD key into the YubiHSM.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param ALGORITHM algorithm: The algorithm to use for the key.
        :param int nonce_id: The nonce ID used for AEADs.
        :param bytes key: The key to import, corresponding to the algorithm.
        :return: A reference to the newly created object.
        :rtype: AsymmetricKey

        """
        msg = struct.pack(
            "!H%dsHQB" % LABEL_LENGTH,
            object_id,
            _label_pack(label),
            domains,
            capabilities,
            algorithm,
        ) + struct.pack(
            "<I", nonce_id
        )  # nonce ID is stored in little-endian.
        msg += key
        return cls._from_command(session, COMMAND.PUT_OTP_AEAD_KEY, msg)

    @classmethod
    def generate(
        cls, session, object_id, label, domains, capabilities, algorithm, nonce_id
    ):
        """Generate a new OTP AEAD key in the YubiHSM.

        :param AuthSession session: The session to import via.
        :param int object_id: The ID to set for the object. Set to 0 to let the
            YubiHSM designate an ID.
        :param str label: A text label to give the object.
        :param int domains: The set of domains to assign the object to.
        :param int capabilities: The set of capabilities to give the object.
        :param ALGORITHM algorithm: The algorithm to use for the key.
        :return: A reference to the newly created object.
        :rtype: OtpAeadKey
        """
        msg = struct.pack(
            "!H%dsHQBL" % LABEL_LENGTH,
            object_id,
            _label_pack(label),
            domains,
            capabilities,
            algorithm,
            nonce_id,
        )
        return cls._from_command(session, COMMAND.GENERATE_OTP_AEAD_KEY, msg)

    def create_otp_aead(self, key, identity):
        """Create a new Yubico OTP credential AEAD.

        :param bytes key: 16 byte AES key for the credential.
        :param bytes identity: 6 byte private ID for the credential.
        :return: A new AEAD.
        :rtype: bytes
        """
        msg = struct.pack("!H", self.id) + key + identity
        return self.session.send_secure_cmd(COMMAND.CREATE_OTP_AEAD, msg)

    def randomize_otp_aead(self):
        """Create a new Yubico OTP credential AEAD using random data.

        :return: A new AEAD.
        :rtype: bytes
        """
        msg = struct.pack("!H", self.id)
        return self.session.send_secure_cmd(COMMAND.RANDOMIZE_OTP_AEAD, msg)

    def decrypt_otp(self, aead, otp):
        """Decrypt a Yubico OTP using an AEAD.

        :param bytes aead: The AEAD containing encrypted credential data.
        :param bytes otp: The 16 byte encrypted OTP payload to decrypt.
        :return: The decrypted OTP data.
        :rtype: OtpData
        """
        msg = struct.pack("!H", self.id) + aead + otp
        resp = self.session.send_secure_cmd(COMMAND.DECRYPT_OTP, msg)
        return OtpData(*struct.unpack("<HBBH", resp))

    def rewrap_otp_aead(self, new_key_id, aead):
        """Decrypt and re-encrypt an AEAD from one key to another.

        :param int new_key_id: The ID of the OtpAeadKey to wrap to.
        :param bytes aead: The AEAD to re-wrap.
        :return: The new AEAD.
        :rtype: bytes
        """
        msg = struct.pack("!HH", self.id, new_key_id) + aead
        return self.session.send_secure_cmd(COMMAND.REWRAP_OTP_AEAD, msg)
