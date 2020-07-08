# Copyright 2013-2018 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import binascii

import pytest

from nacl._sodium import ffi
from nacl.bindings.crypto_stream import (
    crypto_stream_chacha20_KEYBYTES,
    crypto_stream_chacha20_NONCEBYTES,
    crypto_stream_chacha20_ietf_KEYBYTES,
    crypto_stream_chacha20_ietf_NONCEBYTES,
    crypto_stream_xchacha20_KEYBYTES,
    crypto_stream_xchacha20_NONCEBYTES,
    crypto_stream_chacha20_keygen,
    crypto_stream_chacha20_xor,
    crypto_stream_chacha20_xor_ic,
    crypto_stream_xchacha20_keygen,
    crypto_stream_xchacha20_xor,
    crypto_stream_xchacha20_xor_ic,
)
from nacl.utils import random as randombytes

def sodium_is_zero(data):
    d = 0
    for x in data:
        d |= x
    return 1 & ((d - 1) >> 8)

def test_stream_xchacha20():
    vectors = [
        { "key": "79c99798ac67300bbb2704c95c341e3245f3dcb21761b98e52ff45b24f304fc4", "nonce": "b33ffd3096479bcfbc9aee49417688a0a2554f8d95389419", "out": "c6e9758160083ac604ef90e712ce6e75d7797590744e0cf060f013739c" },
        { "key": "ddf7784fee099612c40700862189d0397fcc4cc4b3cc02b5456b3a97d1186173", "nonce": "a9a04491e7bf00c3ca91ac7c2d38a777d88993a7047dfcc4", "out": "2f289d371f6f0abc3cb60d11d9b7b29adf6bc5ad843e8493e928448d" },
        { "key": "3d12800e7b014e88d68a73f0a95b04b435719936feba60473f02a9e61ae60682", "nonce": "56bed2599eac99fb27ebf4ffcb770a64772dec4d5849ea2d", "out": "a2c3c1406f33c054a92760a8e0666b84f84fa3a618f0" },
        { "key": "5f5763ff9a30c95da5c9f2a8dfd7cc6efd9dfb431812c075aa3e4f32e04f53e4", "nonce": "a5fa890efa3b9a034d377926ce0e08ee6d7faccaee41b771", "out": "8a1a5ba898bdbcff602b1036e469a18a5e45789d0e8d9837d81a2388a52b0b6a0f51891528f424c4a7f492a8dd7bce8bac19fbdbe1fb379ac0" },
        { "key": "eadc0e27f77113b5241f8ca9d6f9a5e7f09eee68d8a5cf30700563bf01060b4e", "nonce": "a171a4ef3fde7c4794c5b86170dc5a099b478f1b852f7b64", "out": "23839f61795c3cdbcee2c749a92543baeeea3cbb721402aa42e6cae140447575f2916c5d71108e3b13357eaf86f060cb" },
        { "key": "91319c9545c7c804ba6b712e22294c386fe31c4ff3d278827637b959d3dbaab2", "nonce": "410e854b2a911f174aaf1a56540fc3855851f41c65967a4e", "out": "cbe7d24177119b7fdfa8b06ee04dade4256ba7d35ffda6b89f014e479faef6" },
        { "key": "6a6d3f412fc86c4450fc31f89f64ed46baa3256ffcf8616e8c23a06c422842b6", "nonce": "6b7773fce3c2546a5db4829f53a9165f41b08faae2fb72d5", "out": "8b23e35b3cdd5f3f75525fc37960ec2b68918e8c046d8a832b9838f1546be662e54feb1203e2" },
        { "key": "d45e56368ebc7ba9be7c55cfd2da0feb633c1d86cab67cd5627514fd20c2b391", "nonce": "fd37da2db31e0c738754463edadc7dafb0833bd45da497fc", "out": "47950efa8217e3dec437454bd6b6a80a287e2570f0a48b3fa1ea3eb868be3d486f6516606d85e5643becc473b370871ab9ef8e2a728f73b92bd98e6e26ea7c8ff96ec5a9e8de95e1eee9300c" },
        { "key": "aface41a64a9a40cbc604d42bd363523bd762eb717f3e08fe2e0b4611eb4dcf3", "nonce": "6906e0383b895ab9f1cf3803f42f27c79ad47b681c552c63", "out": "a5fa7c0190792ee17675d52ad7570f1fb0892239c76d6e802c26b5b3544d13151e67513b8aaa1ac5af2d7fd0d5e4216964324838" },
        { "key": "9d23bd4149cb979ccf3c5c94dd217e9808cb0e50cd0f67812235eaaf601d6232", "nonce": "c047548266b7c370d33566a2425cbf30d82d1eaf5294109e", "out": "a21209096594de8c5667b1d13ad93f744106d054df210e4782cd396fec692d3515a20bf351eec011a92c367888bc464c32f0807acd6c203a247e0db854148468e9f96bee4cf718d68d5f637cbd5a376457788e6fae90fc31097cfc" },
    ]

    final_out = "3e34c160a966ddfbd52d38f6a440a77256c1134ad54653db427dfdfc72f0f995768039052ec2ec4e6fe02c655d7d95681fabd417c087ad17f177510ba09d4cfe7beb8f7c9b8330d746310f9e29583e9ef240156015faafeb24a4d002d6337b7bcec8b54a64ef704e1ae3247d79625d267cbacd1c90e4a2df2f72d4090babf88c90e65a086c464ec1753c49d3b8ad02f2a3c0808e1695c5d77cec6f6f12578ae4ed077a2046e06644d14af65ae90f2869a6f1f910b83a7a3cfec8dd390621a511"

    key = bytes()
    nonce = bytes()
    out = bytes()

    for vec in vectors:
        key = binascii.unhexlify(vec["key"])
        nonce = binascii.unhexlify(vec["nonce"])
        out = binascii.unhexlify(vec["out"])

        out2 = crypto_stream_xchacha20_xor(out, nonce, key)
        assert sodium_is_zero(out2)

        out2 = crypto_stream_xchacha20_xor_ic(out, nonce, 0, key)
        assert sodium_is_zero(out2)

        out2 = crypto_stream_xchacha20_xor_ic(out, nonce, 1, key)
        assert not sodium_is_zero(out2)

        out = crypto_stream_xchacha20_xor(out, nonce, key)
        assert sodium_is_zero(out)

    out = randombytes(64)
    out2 = randombytes(64)
    out2 += out

    out = crypto_stream_xchacha20_xor_ic(out, nonce, key)
    out2 = crypto_stream_xchacha20_xor(out2, nonce, key)
    assert out == out2[64:]

    out = b'\x00' * 192
    out2 = b'\x00' * 192

    out2 = crypto_stream_chacha20_xor_ic(out2, nonce, (1 << 32) - 1, key)
    out3 = crypto_stream_xchacha20_xor_ic(out[:64], nonce, (1 << 32) - 1, key)
    out3 += crypto_stream_xchacha20_xor_ic(out[64:128], nonce, (1 << 32), key)
    out3 += crypto_stream_xchacha20_xor_ic(out[128:], nonce, (1 << 32) + 1, key)
    assert out3 == out2

    out3_hex = binascii.hexlify(out3)
    assert final_out == out3_hex

    assert not sodium_is_zero(crypto_stream_xchacha20_keygen())
