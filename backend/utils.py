import bchlib
import hashlib
import os
import random
import string
import io
import soundfile
import json
from machine_learning.speaker_recognition import calc_feat_vec
import numpy as np
from voice_recovery_python import poseidon_hash, evm_prove
from convert import bytearray_to_hex, hex_to_bytearray, feat_bytearray_from_wav_blob


# create a bch object
BCH_POLYNOMIAL = 8219
BCH_BITS = 64  # 誤り訂正可能なビット数
bch = bchlib.BCH(BCH_POLYNOMIAL, BCH_BITS)
CODE_LEN = 140


def generate_filename(length):
    letters = string.ascii_lowercase
    filename = ''.join(random.choice(letters) for i in range(length))
    return filename

# bch符号による誤り訂正


def bch_error_correction(packet):
    '''
    BCH符号による誤り訂正

    Parameters
    ----------
    packet : bytearray
        256ビットのデータをBCHによってエンコードしたもの。256ビットより大きい。
    '''

    # de-packetize
    data, ecc = packet[:-bch.ecc_bytes], packet[-bch.ecc_bytes:]

    # correct
    bitflips = bch.decode_inplace(data, ecc)

    # packetize
    packet = data + ecc

    return packet


def bitflip(packet):
    byte_num = random.randint(0, len(packet) - 1)
    bit_num = random.randint(0, 7)
    packet[byte_num] ^= (1 << bit_num)


def test_bch():
    data = bytearray(os.urandom(32))

    ecc = bch.encode(data)
    packet = data + ecc
    print(type(packet))

    assert packet == bch_error_correction(packet)


def xor(a, b):
    '''
    排他的論理和を取る。

    Parameters
    ----------
    a : bytearray
    b : bytearray
    '''
    result = bytearray([x ^ y for x, y in zip(a, b)])
    return result


def my_hash(data):
    '''
    Poseidonハッシュ関数をとる

    Parameters
    ----------
    data : bytearray
    '''
    return hex_to_bytearray(poseidon_hash(bytearray_to_hex(data)))


def padding(data, n):
    '''
    256ビットになるように0を追加する。

    Parameters
    ----------
    data : bytearray
    n : バイト数
    '''
    padding_data = data.ljust(n, b'\x00')
    return padding_data


def fuzzy_commitment(feat_vec):
    '''
    特徴量ベクトルからh(w)とcを生成する。

    Parameters
    ----------
    feat_vec : bytearray
    '''

    # generate random vector
    s = bytearray(os.urandom(32))

    ecc = bch.encode(s)
    packet = s + ecc
    print("packet is ", bytearray_to_hex(packet))
    print(len(packet))

    feat_vec = padding(feat_vec, len(packet))

    c = xor(feat_vec, packet)

    h_w = my_hash(packet)

    return c, h_w


def recover(feat_vec, c, h_w, m):
    '''
    特徴量ベクトルからwを復元し、eとhash(m,w)を返す。

    Parameters
    ----------
    feat_vec : bytearray
    c : bytearray
    h_w : bytearray
    m : bytearray
    '''
    assert (len(c) >= len(feat_vec))
    l = len(c)
    feat_vec = padding(feat_vec, l)
    w1 = xor(feat_vec, c)
    w = bch_error_correction(w1)

    e = xor(w, w1)

    h_m_w = my_hash(m+w)

    recovered_h_W = my_hash(w)
    print(recovered_h_W)

    return e, h_m_w, recovered_h_W


def generate_proof(feat_vec, err, feat_xor_ecc, message):
    session_id = generate_filename(20)
    session_dir = os.path.join("./storage", session_id)
    print(session_dir)
    # params_dir = "../build/params"
    # pk_dir = "../build/pk"

    os.mkdir(session_dir)
    input_path = os.path.join(session_dir, "input.json")
    input_data = {
        "features": bytearray_to_hex(padding(feat_vec, CODE_LEN)),
        "errors": bytearray_to_hex(padding(err, CODE_LEN)),
        "commitment": bytearray_to_hex(padding(feat_xor_ecc, CODE_LEN)),
        "message": bytearray_to_hex(message)
    }
    input_json = json.dumps(input_data)
    with open(input_path, "w") as f:
        f.write(input_json)

    proof_path = os.path.join(session_dir, "proof.hex")
    public_input_path = os.path.join(session_dir, "public.json")
    try:
        evm_prove(
            params_dir="../build/params",
            app_circuit_config="../eth_voice_recovery/configs/test1_circuit.config",
            agg_circuit_config="../eth_voice_recovery/configs/agg_circuit.config",
            pk_dir="../build/pks",
            input_path=input_path,
            proof_path=proof_path,
            public_input_path=public_input_path
        )
    except:
        return False, b'', session_id
    # 余裕があればpublic inputをアサートする

    with open(proof_path, 'r') as f:
        # hex
        proof_bin = hex_to_bytearray(f.read())
        return True, proof_bin, session_id

    # shutil.rmtree(session_dir)

# # 長さが256ビットの特徴ベクトルを生成
# vec = np.random.randint(0, 2, 256)
# print(vec)
# bin_vec = bytearray(np.packbits(vec))
# print("bin_vec is ",bytearray_to_hex(bin_vec))
# bin_vec = padding(bin_vec, 64)
# print("padding bin_vec is ",bin_vec)
# h_w, c = fuzzy_commitment(bin_vec)
# print ("h_w is ",h_w), print("c is ",c)


def main():
    generate_proof(
        hex_to_bytearray(
            "0xddeb3779c4515c05a06495c3ec2403655d9b784d7502a064ebf3c093474b23ce"),
        hex_to_bytearray("0x00000004410000000010a16008004002028000300200000100025001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
        hex_to_bytearray("0x7d7fbf998b8e8d29756bcea0755e51a2e7208e3d9df90aa741450ced38cddbfcc8a96ccce1daa8bff47472d07907a612a761b2a1ec37d25407a6952020e413ee12f40ca7d81cb0dcab51591c3495c4b63134518969ec7c69b6469f0ab20e3d82ceffe4eda9ed71550f0ac020061eb7907cfd6eb54849fa5c7fc882764d7f815c08f5fee653a47402"),
        hex_to_bytearray("0x9a8f43")
    )


if __name__ == '__main__':
    main()
