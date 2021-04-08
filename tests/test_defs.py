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

from yubihsm.defs import ALGORITHM, CAPABILITY
from cryptography.hazmat.primitives.asymmetric import ec

import pytest


@pytest.mark.parametrize(
    "algorithm, curve",
    [
        (ALGORITHM.EC_P224, ec.SECP224R1),
        (ALGORITHM.EC_P256, ec.SECP256R1),
        (ALGORITHM.EC_P384, ec.SECP384R1),
        (ALGORITHM.EC_P521, ec.SECP521R1),
        (ALGORITHM.EC_K256, ec.SECP256K1),
        (ALGORITHM.EC_BP256, ec.BrainpoolP256R1),
        (ALGORITHM.EC_BP384, ec.BrainpoolP384R1),
        (ALGORITHM.EC_BP512, ec.BrainpoolP512R1),
    ],
)
def test_algorithm_to_from_curve(algorithm, curve):
    assert isinstance(algorithm.to_curve(), curve)
    assert algorithm == ALGORITHM.for_curve(curve())


def test_capability_all_includes_everything():
    assert CAPABILITY.ALL == sum(CAPABILITY)
    assert CAPABILITY.NONE == 0

    for c in CAPABILITY:
        assert c in CAPABILITY.ALL
        assert c not in CAPABILITY.NONE
