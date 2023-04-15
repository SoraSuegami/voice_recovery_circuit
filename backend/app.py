from flask import Flask, jsonify, request
from flask_cors import CORS
from utils import fuzzy_commitment, recover, my_hash
from convert import bytearray_to_hex, hex_to_bytearray, feat_bytearray_from_wav_blob
import numpy as np
import json

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
    feat = feat_bytearray_from_wav_blob(form_file)
    print(bytearray_to_hex(feat))

    feat_xor_ecc, hash_ecc = fuzzy_commitment(feat)
    hash_feat_xor_ecc = my_hash(feat_xor_ecc)  

    ret = {
        "feat" : bytearray_to_hex(feat),
        "hash_ecc" : bytearray_to_hex(hash_ecc),
        "hash_feat_xor_ecc" : bytearray_to_hex(hash_feat_xor_ecc),
        "feat_xor_ecc": bytearray_to_hex(feat_xor_ecc),
    }
    print(ret)

    return jsonify(ret)

"""
特徴量ベクトルを計算し、commitment h(W),cを返す
"""
@app.route('/api/gen-proof', methods=['POST'])
def gen_proof():
    form_file = request.files['file']
    new_feat = feat_bytearray_from_wav_blob(form_file)
    print(bytearray_to_hex(new_feat))

    """
    Request形式
    {
        "hash_ecc" : hex,
        "feat_xor_ecc": hex,
        "msg": hex,
    }
    """
    json_data = json.loads(request.form['jsonData'])
    print(json_data)
    
    hash_ecc = hex_to_bytearray(json_data["hash_ecc"])
    feat_xor_ecc = hex_to_bytearray(json_data["feat_xor_ecc"])
    msg = hex_to_bytearray(json_data["msg"])

    code_error, hash_ecc_msg, recovered_hash_ecc = recover(new_feat, feat_xor_ecc, hash_ecc, msg)

    ret = {
        "new_feat": bytearray_to_hex(new_feat),
        "recovered_hash_ecc" : bytearray_to_hex(recovered_hash_ecc),
        "hash_ecc_msg": bytearray_to_hex(hash_ecc_msg),
        "code_error": bytearray_to_hex(code_error),
    }
    print(ret)

    return jsonify(ret)

if __name__ == '__main__':
    app.run()