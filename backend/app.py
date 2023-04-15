from flask import Flask, jsonify, request
from flask_cors import CORS
import io
import soundfile
from machine_learning.speaker_recognition import calc_feat_vec

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

@app.route('/api/feature-vector', methods=['POST'])
def feat_vec():
    form_file = request.files['file']
    file_data = io.BytesIO(form_file.read())

    audio, sample_rate = soundfile.read(file_data)

    vec = calc_feat_vec(audio, sample_rate)

    return jsonify(vec.tolist())

if __name__ == '__main__':
    app.run()