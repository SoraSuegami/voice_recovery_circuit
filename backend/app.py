from flask import Flask, jsonify, request
from flask_cors import CORS
import io
import soundfile
from machine_learning.speaker_recognition import calc_feat_vec
from utils import fuzzy_commitment, bytearray_to_hex
import numpy as np

app = Flask(__name__)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.route('/api/data')
def get_data():
    data = {'name': 'John', 'age': 30}
    return jsonify(data)
    

@app.route('/api/upload-wav', methods=['POST'])
def upload():
    file = request.files['file']

    file.save('storage/recorded.wav')

    return {'message': 'File uploaded successfully'}

"""
特徴量ベクトルを計算し、commitment h(W),cを返す
"""
@app.route('/api/feature-vector', methods=['POST'])
def feat_vec():
    form_file = request.files['file']
    file_data = io.BytesIO(form_file.read())

    audio, sample_rate = soundfile.read(file_data)

    feat_vec = calc_feat_vec(audio, sample_rate)
    print(feat_vec)

    feat_bytearray = bytearray(np.packbits(feat_vec))
    print(feat_bytearray)

    feat_xor_ecc, hash_ecc = fuzzy_commitment(feat_bytearray)    

    ret = {
        "feat" : bytearray_to_hex(feat_bytearray),
        "hash_ecc" : bytearray_to_hex(hash_ecc),
        "feat_xor_ecc": bytearray_to_hex(feat_xor_ecc),
    }
    print(ret)

    return jsonify(ret)

if __name__ == '__main__':
    app.run()