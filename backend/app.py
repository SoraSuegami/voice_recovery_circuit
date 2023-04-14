from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.route('/api/data')
def get_data():
    data = {'name': 'John', 'age': 30}
    return jsonify(data)

if __name__ == '__main__':
    app.run()