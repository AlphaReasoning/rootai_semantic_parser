from flask import request
import os

@app.route('/run')
def run_cmd():
    user_input = request.args.get('cmd')
    os.system(user_input) # Target Sink
