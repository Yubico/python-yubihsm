# coding=utf-8

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

from __future__ import absolute_import, division, unicode_literals

from yubihsm.utils import password_to_key
from binascii import a2b_hex

import unittest


class TestUtils(unittest.TestCase):
    def test_password_to_key(self):
        self.assertEqual(
            (
                a2b_hex('090b47dbed595654901dee1cc655e420'),
                a2b_hex('592fd483f759e29909a04c4505d2ce0a')
            ), password_to_key('password')
        )

        self.assertEqual(
            (
                a2b_hex('090b47dbed595654901dee1cc655e420'),
                a2b_hex('592fd483f759e29909a04c4505d2ce0a')
            ), password_to_key(b'password')
        )

    def test_password_to_key_utf8(self):
        self.assertEqual(
            (
                a2b_hex('f320972c667ba5cd4d35119a6b0271a1'),
                a2b_hex('f10050ca688e5a6ce62b1ffb0f6f6869')
            ), password_to_key('κόσμε')
        )

        self.assertEqual(
            (
                a2b_hex('f320972c667ba5cd4d35119a6b0271a1'),
                a2b_hex('f10050ca688e5a6ce62b1ffb0f6f6869')
            ), password_to_key(a2b_hex('cebae1bdb9cf83cebcceb5'))
        )
