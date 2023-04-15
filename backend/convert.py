import os
import io
import soundfile
import numpy as np
from machine_learning.speaker_recognition import calc_feat_vec


def bytearray_to_hex(ba) :
    return '0x' + ''.join(format(x, '02x') for x in ba)

def hex_to_bytearray(hex_string):
    return bytearray.fromhex(hex_string[2:])

def feat_bytearray_from_wav_blob(wav_form_file):
    file_data = io.BytesIO(wav_form_file.read())
    audio, sample_rate = soundfile.read(file_data)
    feat_vec = calc_feat_vec(audio, sample_rate)
    feat_bytearray = bytearray(np.packbits(feat_vec))
    return feat_bytearray