import bchlib
import hashlib
import os
import random

# bch符号による誤り訂正
def bch_error_correction(packet):
    '''
    BCH符号による誤り訂正

    Parameters
    ----------
    packet : bytearray
        256ビットのデータをBCHによってエンコードしたもの。256ビットより大きい。
    '''
    
    # create a bch object
    BCH_POLYNOMIAL = 8219
    BCH_BITS = 64 #誤り訂正可能なビット数
    bch = bchlib.BCH(BCH_POLYNOMIAL, BCH_BITS)

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
    # create a bch object
    BCH_POLYNOMIAL = 8219
    BCH_BITS = 64 #誤り訂正可能なビット数
    bch = bchlib.BCH(BCH_POLYNOMIAL, BCH_BITS)

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