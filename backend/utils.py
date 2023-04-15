import bchlib
import hashlib
import os
import random
from machine_learning.speaker_recognition import calc_feat_vec
import numpy as np


# create a bch object
BCH_POLYNOMIAL = 8219
BCH_BITS = 64 #誤り訂正可能なビット数
bch = bchlib.BCH(BCH_POLYNOMIAL, BCH_BITS)

def bytearray_to_hex(ba) :
    return '0x' + ''.join(format(x, '02x') for x in ba)

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

def hash(data):
    '''
    ハッシュ関数(SHA256)を取る。

    Parameters
    ----------
    data : bytearray
    '''
    return hashlib.sha256(data).digest() 

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
    print("packet is ",bytearray_to_hex(packet))
    print(len(packet))
    
    feat_vec = padding(feat_vec, len(packet))

    c = xor(feat_vec, packet)

    h_w = hash(packet)

    return c, h_w

def recover(feat_vec, c, h_w, m):
    '''
    特徴量ベクトルからwを復元し、eとhash(m,w)を返す。

    Parameters
    ----------
    feat_vec : bytearray
    c : bytearray
    h_w : 
    m : stirng
    '''

    w1 = xor(feat_vec, c)
    w = bch_error_correction(w1)

    e = xor(w, w1)

    h_m_w = hash(m.encode()+w)

    return e, h_m_w

#長さが256ビットの特徴ベクトルを生成
# vec = np.random.randint(0, 2, 256)
#print(vec)
# bin_vec = bytearray(np.packbits(vec))
# print("bin_vec is ",bytearray_to_hex(bin_vec))
# bin_vec = padding(bin_vec, 64)
# print("padding bin_vec is ",bin_vec)
# h_w, c = fuzzy_commitment(bin_vec)
# print ("h_w is ",h_w), print("c is ",c)
