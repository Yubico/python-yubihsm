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

from yubihsm.defs import ALGORITHM
from yubihsm.defs import BRAINPOOLP256R1, BRAINPOOLP384R1, BRAINPOOLP512R1
from cryptography.hazmat.primitives.asymmetric import ec

import unittest


class TestAlgorithm(unittest.TestCase):
    def test_to_curve(self):
        self.assertIsInstance(ALGORITHM.EC_P224.to_curve(), ec.SECP224R1)
        self.assertIsInstance(ALGORITHM.EC_P256.to_curve(), ec.SECP256R1)
        self.assertIsInstance(ALGORITHM.EC_P384.to_curve(), ec.SECP384R1)
        self.assertIsInstance(ALGORITHM.EC_P521.to_curve(), ec.SECP521R1)
        self.assertIsInstance(ALGORITHM.EC_K256.to_curve(), ec.SECP256K1)
        self.assertIsInstance(ALGORITHM.EC_BP256.to_curve(), BRAINPOOLP256R1)
        self.assertIsInstance(ALGORITHM.EC_BP384.to_curve(), BRAINPOOLP384R1)
        self.assertIsInstance(ALGORITHM.EC_BP512.to_curve(), BRAINPOOLP512R1)

    def test_for_curve(self):
        self.assertEqual(ALGORITHM.for_curve(ec.SECP224R1()), ALGORITHM.EC_P224)
        self.assertEqual(ALGORITHM.for_curve(ec.SECP256R1()), ALGORITHM.EC_P256)
        self.assertEqual(ALGORITHM.for_curve(ec.SECP384R1()), ALGORITHM.EC_P384)
        self.assertEqual(ALGORITHM.for_curve(ec.SECP521R1()), ALGORITHM.EC_P521)
        self.assertEqual(ALGORITHM.for_curve(ec.SECP256K1()), ALGORITHM.EC_K256)
        self.assertEqual(ALGORITHM.for_curve(BRAINPOOLP256R1()), ALGORITHM.EC_BP256)
        self.assertEqual(ALGORITHM.for_curve(BRAINPOOLP384R1()), ALGORITHM.EC_BP384)
        self.assertEqual(ALGORITHM.for_curve(BRAINPOOLP512R1()), ALGORITHM.EC_BP512)
