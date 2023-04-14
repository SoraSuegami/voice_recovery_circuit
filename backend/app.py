from flask import Flask, jsonify, request
from flask_cors import CORS

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

if __name__ == '__main__':
    app.run()