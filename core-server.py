#!/bin/python3

from tracemalloc import start
from flask import Flask, request
import sys, getopt, os
import base64
import json
import time
import hmac

# 先撰写直接接收文件和命令的代码

app = Flask(__name__)

dev_mode = True

thekey = ""

# 生成Token：https://blog.csdn.net/xc_zhou/article/details/80687825

def generate_token(key, expire=300):
    r'''
        @Args:
            key: str (用户给定的key，需要用户保存以便之后验证token,每次产生token时的key 都可以是同一个key)
            expire: int(最大有效时间，单位为s)
        @Return:
            state: str
    '''
    ts_str = str(time.time() + expire)
    ts_byte = ts_str.encode("utf-8")
    sha1_tshexstr  = hmac.new(key.encode("utf-8"),ts_byte,'sha1').hexdigest() 
    token = ts_str+':'+sha1_tshexstr
    b64_token = base64.urlsafe_b64encode(token.encode("utf-8"))
    return b64_token.decode("utf-8")

def certify_token(key, token):
    r'''
        @Args:
            key: str
            token: str
        @Returns:
            boolean
    '''
    token_str = base64.urlsafe_b64decode(token).decode('utf-8')
    token_list = token_str.split(':')
    if len(token_list) != 2:
        return False
    ts_str = token_list[0]
    if float(ts_str) < time.time():
        # token expired
        return False
    known_sha1_tsstr = token_list[1]
    sha1 = hmac.new(key.encode("utf-8"),ts_str.encode('utf-8'),'sha1')
    calc_sha1_tsstr = sha1.hexdigest()
    if calc_sha1_tsstr != known_sha1_tsstr:
        # token certification failed
        return False 
    # token certification success
    return True 

def check_config_exists(dir,value):
    try: 
        dir[value]
    except KeyError:
        return(False)
    else:
        return(True)

def main(argv):
    ConfigFile = ""
    HelpInfo = "Usage: coer-server.py [-c <config file>/--config=<config file>]"
    try:
        opts, args = getopt.getopt(argv,"hc:",["help","config="])
    except getopt.GetoptError:
        print(HelpInfo)
        return()

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(HelpInfo)
            sys.exit()
        elif opt in ("-c", "--config"):
            ConfigFile = arg
    
    if (ConfigFile == ""):
        print("Error!\n"+HelpInfo)
        return()
    
    listening="0.0.0.0"
    port=5000
    global config_data
    with open(ConfigFile, 'r') as configfile:
        config_data=json.load(configfile)
    print(config_data)
    app.config.from_file(ConfigFile, load=json.load)
    print(app.config)
    if check_config_exists(config_data,'apiHostSetting'):
        if check_config_exists(config_data['apiHostSetting'],"Listening"):
            listening=config_data['apiHostSetting']["Listening"]
        if check_config_exists(config_data['apiHostSetting'],"port"):
            port=config_data['apiHostSetting']["port"]
    print("Listen Address: ",listening)
    print("Port: ",port)
    app.run(
        host=listening,
        port=port
    )

def auth(chiper):
    success_msg = "success"
    fail_msg = "fail"
    thekey=config_data['key']
    print(chiper)
    print(thekey)
    result = {}
    if chiper == thekey:
        result={
            "token": generate_token(thekey+config_data['id']),
            "status": success_msg
        }
        
    else:
        result={
            "status":fail_msg
        }
    return result

def upload(token,location,fileBase64):
    success_msg = "success"
    fail_msg = "fail"
    print(token,"\n",location,"\n",fileBase64)
    result={}
    if certify_token(config_data['key']+config_data['id'],token):
        with open(location,'w') as file:
            file.write(base64.b64decode(fileBase64).decode('ascii'))
        result={
            "status":success_msg
        }
    else:
        result={
            "status":fail_msg
        }
    return json.dumps(result)

def apply(token,commandBase64):
    success_msg = "success"
    fail_msg = "fail"
    if certify_token(config_data['key']+config_data['id'],token):
        cmd_out=os.system(base64.b64decode(commandBase64).decode('ascii'))
        print(cmd_out)
        result={
            "status":success_msg,
            "cmdOut":cmd_out
        }
    else:
        result={
            "status":fail_msg
        }
    return json.dumps(result)

@app.route('/auth', methods=['GET', 'POST'])
def auth_page():
    chiper = request.args.get('login')
    result = auth(chiper)
    return result

@app.route('/upload', methods=['GET', 'POST'])
def upload_page():
    token = request.form['token']
    location = request.form['location']
    fileBase64 = request.form['fileBase64']
    result = upload(token,location,fileBase64)
    return json.dumps(result)

@app.route('/apply', methods=['GET', 'POST'])
def apply_page():
    token = request.form['token']
    commandBase64 = request.form['commandBase64']
    result = apply(token,commandBase64)
    return json.dumps(result)


if __name__ == '__main__':
    main(sys.argv[1:])
    