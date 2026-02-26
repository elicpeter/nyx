from flask import Flask, request
import yaml

app = Flask(__name__)

@app.route('/parse', methods=['POST'])
def parse_config():
    data = request.get_data()
    config = yaml.load(data, Loader=yaml.FullLoader)
    return str(config)

@app.route('/parse-safe', methods=['POST'])
def parse_config_safe():
    data = request.get_data()
    config = yaml.safe_load(data)
    return str(config)
