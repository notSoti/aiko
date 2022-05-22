from flask import Flask
from threading import Thread

app = Flask(__name__)

@app.route('/')
def main():
    return "<code>Aiko! prod version. You shouldn't be here.<code>"

def run():
    app.run(host="0.0.0.0", port=8080)

def keep_alive():
    server = Thread(target=run)
    server.start()

keep_alive()