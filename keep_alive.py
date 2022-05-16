from flask import Flask
from threading import Thread

app = Flask(__name__)

@app.route('/')
def main():
    return "Aiko! prod version. If you're somehow seeing this then hi you could say this is an easter egg!"

def run():
    app.run(host="0.0.0.0", port=8080)

def keep_alive():
    server = Thread(target=run)
    server.start()

keep_alive()