# donna25519,paramiko

import binascii
import tempfile
import donna25519 as curve25519
import sys, getopt, os
import paramiko
import base64
import hashlib
import re
import json,requests

dev_mode=False

def main(argv):
    ConfigFile = ""
    uploadBool = False
    confSavepath= "./"
    HelpInfo = "Usage: geninfo.py [-c <config file>/--config=<config file>] [-u/--upload] [-l/--local-path=<config save path>]"
    try:
        opts, args = getopt.getopt(argv,"hc:ul:",["help","config=","upload","local-path="])
    except getopt.GetoptError:
        print(HelpInfo)
        return()

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(HelpInfo)
            sys.exit()
        elif opt in ("-c", "--config"):
            ConfigFile = arg
        elif opt in ("-u", "--upload"):
            uploadBool = True
        elif opt in ("-l", "--local-path"):
            confSavepath = arg
        
    #print(MainKey,CoreID,PublicIPAddress,Mode)
    #return()
    if (ConfigFile == ""):
        print("Error!\n"+HelpInfo)
        return()
    start=nodeItem(ConfigFile)
    if ConfigFile != "":
        start.saveGenconfig(confSavepath)
    if uploadBool == True:
        start.uploadConfigs(upmode='url')
        return()

def check_config_exists(dir,value):
    try: 
        dir[value]
    except KeyError:
        return(False)
    else:
        return(True)

def string_to_file(string):
    file_like_obj = tempfile.NamedTemporaryFile()
    file_like_obj.write(string)
    # 确保string立即写入文件
    file_like_obj.flush()
    # 将文件读取指针返回到文件开头位置
    file_like_obj.seek(0)
    return file_like_obj

class nodeItem:
    def __init__(self,configfile) -> None:
        with open(configfile, 'r') as self.configfile:
            self.config_data=json.load(self.configfile)
        self.nodes=[]
        self.IDs=[]
        if not self.config_data['asnPrefix']:
            self.asnprefix="000"
        else:
            self.asnprefix=self.config_data['asnPrefix']
        self.mainkey=self.config_data['MainKey']
        self.loadIDList()
        self.createNodes()
        self.createWGs()
        self.Preshare_key=""
        
        if check_config_exists(self.config_data,'SSHKeyfile'):
            self.SSHKeyfile=open(self.config_data['SSHKeyfile'])
        if check_config_exists(self.config_data,'Preshare-key'):
            self.Preshare_key=self.config_data['Preshare-key']
        

    def loadIDList(self):
        for i in self.config_data['CoreNodes']:
            self.IDs.append(i['id'])
    

    def createNodes(self) -> None:
        count_var=0
        for i in self.config_data['CoreNodes']:
            self.nodes.append(corenode(self.mainkey,i['id'],i['ip']))
            net4_list=[]
            net6_list=[]

            # 判断配置表项是否有privateKey、linkto-port、asn、linkType、
            # natSetting、network4、network6等

            checklist={
                'privateKey': False,
                'linkto-port': False,
                'asn': False,
                'linkType': False,
                'natSetting': False,
                'network4': False,
                'network6': False,
                'linkLocalv4': False,
                'linkLocalv6': False,
                'noSystemd': False
            }

            for x in checklist:
                checklist[x]=check_config_exists(i,x)

            if check_config_exists(self.config_data,'IPv6Disable'):
                if self.config_data['IPv6Disable'] == True:
                    self.nodes[count_var].IPv6Disable = True
            
            if checklist['network4']:
                for x in i['network4']:
                    net4_list.append(x)

            if checklist['network6']:
                for x in i['network6']:
                    net6_list.append(x)

            if checklist['privateKey'] : 
                self.nodes[count_var].PrivateKey(i['privateKey'])
                self.nodes[count_var].PublicKey()

            if checklist['linkto-port']:
                self.nodes[count_var].port(i['linkto-port'])

            if checklist['asn']:
                self.nodes[count_var].asn(i['asn'])
            
            if checklist['linkType']:
                if i['linkType']=='nat':
                    self.nodes[count_var].isNat=True
                    self.haveNatcore=True
                    if checklist['natSetting']:
                        self.nodes[count_var].natSetting=i['natSetting']
                    self.nodes[count_var].natApply()
                else:
                    self.haveNatcore=False
            else:
                self.haveNatcore=False
            
            if checklist['linkLocalv4']:
                self.nodes[count_var].linkLocalv4=i['linkLocalv4']

            if checklist['linkLocalv6']:
                self.nodes[count_var].linkLocalv6=i['linkLocalv6']
            
            if checklist['noSystemd']:
                self.nodes[count_var].noSystemd=i['noSystemd']
            


            self.nodes[count_var].router_id=i['router_id']

            self.nodes[count_var].network4=net4_list
            self.nodes[count_var].network6=net6_list
            self.nodes[count_var].frrConfigcontent=self.nodes[count_var].frrConfig(i['router_id'],self.nodes,net4_list,net6_list,self.asnprefix)

            try: 
                i['controlMethod']
            except KeyError:
                controlMethod_exists=False
            else:
                controlMethod_exists=True
                if i['controlMethod'] == 'ssh':
                    self.nodes[count_var].sshSetting = i['sshSetting']
                if i['controlMethod'] == 'url':
                    self.nodes[count_var].urlupSetting = i['urlupSetting']
            count_var = count_var+1

    def createWGs(self):
        for i in self.nodes:
            for x in self.nodes:
                if i.CoreID != x.CoreID:
                    i.wgfiles.append(i.wgConfig(x))
    
    def saveGenconfig(self,rootpath="./"):
        frrDefaultPath="/etc/frr"
        wireguardDefaultPath="/etc/wireguard"
        for i in self.nodes:
            path=rootpath+i.CoreID
            folder = os.path.exists(path)
            if not folder: 
                x = [frrDefaultPath,wireguardDefaultPath]
                for y in x:
                    os.makedirs(path+y)
            frrPath=path+frrDefaultPath
            wireguardPath=path+wireguardDefaultPath
            i.frrConfigcontent=i.frrConfig(i.router_id,self.nodes,i.network4,i.network6)
            with open(frrPath+'/frr.conf','w') as frrfile:
                frrfile.write(i.frrConfigcontent)

            if self.haveNatcore:
                natfileconf=i.natConfig(self.nodes)
                with open(wireguardPath+'/nat_mesh.conf','w') as natwgfile:
                    natwgfile.write(natfileconf)

            for wgfile in i.wgfiles:
                with open(wireguardPath+"/"+wgfile['Peer']+".conf",'w') as wgopen:
                    wgopen.write(wgfile['Config'])

    def uploadConfigs(self,upmode="url"):
        frrDefaultPath="/etc/frr/"
        wireguardDefaultPath="/etc/wireguard/"
        for i in self.nodes:
            if i.noSystemd:
                commands=[
                    'service frr reload'
                ]
            else:
                commands=[
                    'systemctl reload frr'
                ]
            commandsAll=''
            if self.haveNatcore:
                commands.append('wg-quick down nat-mesh; wg-quick up nat-mesh')
            for x in i.wgfiles:
                #commands.append('cat > /etc/wireguard/'+x['Peer']+'.conf << EOF\n'+x['Config']+'\nEOF')
                commands.append('wg-quick down '+x['Peer']+'; wg-quick up '+x['Peer'])
            for x in commands:
                commandsAll = commandsAll+'\n'+ x
            if dev_mode == True:
                print('\n\nDev env...To '+i.CoreID)
                print('Login address: '+i.sshSetting['user']+"@"+i.sshSetting['address'])
                print('SSH Port: '+"-p "+str(i.sshSetting['port']))
                print("Command: "+commandsAll)
            elif dev_mode == False:
                if upmode == 'ssh':
                    ssh = paramiko.SSHClient()
                    trans = paramiko.Transport((i.sshSetting['address'], i.sshSetting['port']))
                    pk=paramiko.RSAKey.from_private_key(self.SSHKeyfile)
                    trans.connect(username=i.sshSetting['user'],pkey=pk)
                    sftp = paramiko.SFTPClient.from_transport(trans)
                    for wgfile in i.wgfiles:
                        sftp.putfo(string_to_file(wgfile['Config'].encode('ascii')),wireguardDefaultPath+wgfile['Peer']+'.conf')
                    if self.haveNatcore:
                        natfileconf=i.natConfig(self.nodes)
                        sftp.putfo(string_to_file(natfileconf.encode('ascii')),wireguardDefaultPath+'nat_mesh.conf')
                    i.frrConfigcontent=i.frrConfig(i.router_id,self.nodes,i.network4,i.network6)
                    sftp.putfo(string_to_file(i.frrConfigcontent.encode('ascii')),frrDefaultPath+'/frr.conf')
                    #ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    #ssh.connect(hostname=i.sshSetting['address'],port=i.sshSetting['port'],username=i.sshSetting['user'],pkey=pk)
                    ssh._transport = trans
                    for x in commands:
                        stdin, stdout, stderr = ssh.exec_command(x)
                        print(stdout.read().decode('utf-8'))
                        #commandsAll = commandsAll+'\n'+ x+'\n'
                    trans.close()
                    
                    ssh.close()

                    # 此处有BUG，只能循环一次便无法使用
                if upmode == 'url':
                    # 含有auth、upload、apply三个api方法

                    # 获取Token
                    loginAuth = {"login":self.Preshare_key}
                    tokenjson=requests.get(i.urlupSetting['apiURL']+"/auth",loginAuth).content
                    print(tokenjson)
                    if json.loads(tokenjson)['status'] == 'fail':
                        print('Wrong key!')
                        return 1
                    token=json.loads(tokenjson)['token']
                    print(token)
                    # 上传文件
                    for wgfile in i.wgfiles: # WGfile upload
                        uploadInfo = {
                            "token":token,
                            "location":wireguardDefaultPath+wgfile['Peer']+'.conf',
                            "fileBase64":base64.b64encode(wgfile['Config'].encode('ascii'))
                        }
                        result=requests.post(i.urlupSetting['apiURL']+"/upload",data=uploadInfo).content
                        print(result)
                    if self.haveNatcore:
                        natfileconf=i.natConfig(self.nodes)
                        uploadInfo = {
                            "token":token,
                            "location":wireguardDefaultPath+'nat_mesh.conf',
                            "fileBase64":base64.b64encode(natfileconf.encode('ascii'))
                        }
                        print(requests.post(i.urlupSetting['apiURL']+"/upload",data=uploadInfo).content)
                    i.frrConfigcontent=i.frrConfig(i.router_id,self.nodes,i.network4,i.network6)
                    uploadInfo = {
                        "token":token,
                        "location":frrDefaultPath+'/frr.conf',
                        "fileBase64":base64.b64encode(i.frrConfigcontent.encode('ascii'))
                    }
                    result=requests.post(i.urlupSetting['apiURL']+"/upload",data=uploadInfo).content
                    print(result)
                    # 应用配置
                    commandInfo = {
                        "token":token,
                        "commandBase64":base64.b64encode(commandsAll.encode('ascii'))
                    }
                    result=requests.post(i.urlupSetting['apiURL']+"/apply",data=commandInfo).content
                    print("Apply result: ",result)
                    pass
        return()


class corenode:

    def __init__(self, MainKey, CoreID, PublicIPAddress="",privatekey=""):
        self.MainKey=MainKey
        self.CoreID=CoreID
        self.IP=PublicIPAddress
        self.isNat=False
        self.natPublicIP=PublicIPAddress
        self.network4=[]
        self.network6=[]
        self.wgfiles=[]
        self.frrConfigcontent = ""
        self.sshSetting = {}
        self.PrivateKey_Value = {
            "base64": "",
            "obj": ""
        }
        self.PublicKey_Value = {
            "base64": "",
            "obj": ""
        }
        self.asn_Value=""
        self.port_Value=""
        self.router_id=""
        self.linkLocalv4=""
        self.linkLocalv6=""
        self.natSetting={}
        self.PrivateKey(privatekey)
        self.PublicKey()
        self.IPv6Disable=False
        self.urlupSetting = {}
        self.noSystemd=False

    def natApply(self):

        def genkey(obj):
            MidSec = obj.midsec("nat")
            obj.natSetting['PrivateKey_Value']['obj']=curve25519.PrivateKey(MidSec[:32].encode('ascii'))
            obj.natSetting['PrivateKey_Value']['base64']=binascii.b2a_base64(obj.natSetting['PrivateKey_Value']["obj"].private).decode('ascii').replace('\n','')
            obj.natSetting['PublicKey_Value']["obj"] = self.PrivateKey(obj.natSetting['PrivateKey_Value']["base64"],"obj").get_public()
            obj.natSetting['PublicKey_Value']["base64"] = binascii.b2a_base64(obj.natSetting['PublicKey_Value']["obj"].public).decode('ascii').replace('\n','')

        def genport(obj):
            MidSec = obj.midsec()
            PortHex = MidSec[:4]
            # 裁切4位，端口号有4位16进制数字（16bit）
            Port = int(PortHex,16)
            if Port < 10000:
                if Port > 5535:
                    Port = (int(MidSec,16) % 6) * 10000 + Port
                else:
                    Port = (int(MidSec,16) % 7) * 10000 + Port
            # 为低于10000的端口添加到高于10000，避免低端口号
            return(str(Port))
        
        def genlinklocal(obj):
            MidSec = obj.midsec()
            Ipv6InHex = MidSec[:28]
            # 裁切28位，IPv6有32位16进制数字，这里取28位作为后缀
            Ipv6InHexList = re.findall(r".{4}", Ipv6InHex)
            # 分割为每4位的数组
            Ipv6Formatted = "fe80:"+":".join(str(x) for x in Ipv6InHexList)+"/128"
            # 添加IPv6本地链路前缀，格式化IPv6
            return(Ipv6Formatted)
        
        if not self.isNat:
            self.natSetting["wgPort"]={}
            self.natSetting["wgPort"]["wanPort"]=genport(self)
            self.natSetting["wgPort"]["lanPort"]=genport(self)

        if not check_config_exists(self.natSetting,"wgPort"):
            return 1
        
        if not check_config_exists(self.natSetting,"linkLocalv6"):
            self.natSetting["linkLocalv6"]=genlinklocal(self)
        
        if not check_config_exists(self.natSetting,"PrivateKey_Value"):
            self.natSetting["PrivateKey_Value"]={}
            self.natSetting["PublicKey_Value"]={}
            genkey(self)
        

        # change common setting

        #self.natSetting={
        #    "wgPort":{
        #        "wanPort":"",
        #        "lanPort":""
        #    },
        #    "linkLocalv6":"",
        #    "PrivateKey_Value": {
        #        "base64": "",
        #        "obj": ""
        #    },
        #    "PublicKey_Value":{
        #        "base64": "",
        #        "obj": ""
        #    }
        #}
    
    def natConfig(self,Peerlist):

        def wgInterfaceUnit(prikey,address,port):
            header='[Interface]\n'
            prikeytext='PrivateKey = '+prikey+'\n'
            addresstext='Address = '+address+'\n'
            porttext='ListenPort = '+port+'\n'
            return(header+prikeytext+addresstext+porttext)

        def wgPeerConfigUnit(pubkey,iplist,endpoint):
            header='[Peer]\n'
            pubkeytext = 'PublicKey = '+pubkey+'\n'
            ips='AllowedIPs = '+iplist+'\n'
            endpointtext = 'Endpoint = '+endpoint+'\n'
            return(header+pubkeytext+ips+endpointtext)
        
        self.natApply()
        prikey=self.natSetting['PrivateKey_Value']['base64']
        address=self.natSetting['linkLocalv6']
        listenport=self.natSetting['wgPort']['wanPort']
        interfaceconfig=wgInterfaceUnit(prikey,address,listenport)

        peerconfig=""

        for i in Peerlist:
            if i.CoreID != self.CoreID:
                i.natApply()
                peerconfig=peerconfig+wgPeerConfigUnit(i.natSetting['PublicKey_Value']['base64'],i.natSetting['linkLocalv6'],i.IP+":"+i.natSetting['wgPort']['wanPort'])


        return(interfaceconfig+peerconfig)
        


    def PrivateKey(self, PrivateKey="", format="base64"):
        if PrivateKey:
            self.PrivateKey_Value["base64"] = PrivateKey
            self.PrivateKey_Value["obj"] = curve25519.PrivateKey.load(binascii.a2b_base64(self.PrivateKey_Value["base64"]))
            return(self.PrivateKey_Value[format])
        MidSec = self.midsec()
        self.PrivateKey_Value["obj"] = curve25519.PrivateKey(MidSec[:32].encode('ascii'))
        # 裁切32位并当做ascii编码成byte类型。
        self.PrivateKey_Value["base64"] = binascii.b2a_base64(self.PrivateKey_Value["obj"].private).decode('ascii').replace('\n','')
        # donna25519输出的时候是byte，我们需要转换成base64之后转为字符串，再去除最后的换行符
        
        return(self.PrivateKey_Value[format])
    
    def PublicKey(self, PublicKey_b64="", format="base64"):

        if PublicKey_b64:
            self.PublicKey_Value["base64"] = PublicKey_b64
            self.PublicKey_Value["obj"] = curve25519.PublicKey(binascii.a2b_base64(PublicKey_b64))
            return(self.PublicKey_Value[format])
        elif (self.PrivateKey_Value["base64"]!="") & (self.PrivateKey_Value["obj"]!=""):
            self.PublicKey_Value["obj"] = self.PrivateKey(self.PrivateKey_Value["base64"],"obj").get_public()
            self.PublicKey_Value["base64"] = binascii.b2a_base64(self.PublicKey_Value["obj"].public).decode('ascii').replace('\n','')
            return(self.PublicKey_Value[format])
        elif self.PrivateKey_Value["base64"] & (not self.PrivateKey_Value["obj"]):
            self.PublicKey_Value["obj"] = self.PrivateKey(binascii.a2b_base64(self.PrivateKey_Value["base64"]),"obj").get_public()
            self.PublicKey_Value["base64"] = binascii.b2a_base64(self.PublicKey_Value["obj"].public).decode('ascii').replace('\n','')
            return(self.PublicKey_Value[format])
        elif self.PrivateKey_Value["obj"] & (not self.PrivateKey_Value["base64"]):
            self.PublicKey_Value["obj"]=self.PrivateKey_Value["obj"].get_public()
            self.PublicKey_Value["base64"] = binascii.b2a_base64(self.PublicKey_Value["obj"].public).decode('ascii').replace('\n','')
            return(self.PublicKey_Value[format])
            
       # MidSec = self.midsec()
       # self.PublicKey_Value["obj"] = curve25519.PrivateKey(MidSec[:32].encode('ascii')).get_public()
       # self.PublicKey_Value["base64"] = binascii.b2a_base64(PublicKey.public).decode('ascii').replace('\n','')
       # return(self.PublicKey_Value["base64"])

    def ipv4(self):
        if self.linkLocalv4:
            return(self.linkLocalv4)
        else:
            MidSec = self.midsec()
            Ipv4InHex = MidSec[:4]
            # 裁切4位
            Ipv4InHexList = re.findall(r".{2}", Ipv4InHex)
            # 分割为每两位的数组
            Ipv4Formatted = "169.254."+".".join(str(int(x,16)) for x in Ipv4InHexList)
            # 添加IPv4本地链路的地址前缀，格式化IPv4
            return(Ipv4Formatted)

    def ipv6(self):
        if self.linkLocalv6:
            return(self.linkLocalv6)
        else:
            MidSec = self.midsec()
            Ipv6InHex = MidSec[:28]
            # 裁切28位，IPv6有32位16进制数字，这里取28位作为后缀
            Ipv6InHexList = re.findall(r".{4}", Ipv6InHex)
            # 分割为每4位的数组
            Ipv6Formatted = "fe80:"+":".join(str(x) for x in Ipv6InHexList)
            # 添加IPv6本地链路前缀，格式化IPv6
            return(Ipv6Formatted)

    def port(self, myPort=""):
        if myPort:
            self.port_Value=myPort
            return(myPort)
        elif self.port_Value:
            return(self.port_Value)
        else:
            MidSec = self.midsec()
            PortHex = MidSec[:4]
            # 裁切4位，端口号有4位16进制数字（16bit）
            Port = int(PortHex,16)
            if Port < 10000:
                if Port > 5535:
                    Port = (int(MidSec,16) % 6) * 10000 + Port
                else:
                    Port = (int(MidSec,16) % 7) * 10000 + Port
            # 为低于10000的端口添加到高于10000，避免低端口号
            return(str(Port))

    def midsec(self,key3=""):
        # 将主密钥与ID转为Base64之后，将字符串衔接，计算SHA256，并且取Hex字符串
        key1=self.MainKey
        key2=self.CoreID
        key1_base64 = base64.b64encode(key1.encode('ascii'))
        key2_base64 = base64.b64encode(key2.encode('ascii'))
        key3_base64 = base64.b64encode(key3.encode('ascii'))
        return(hashlib.sha256(key1_base64+key2_base64+key3_base64).hexdigest())

    def wgConfig(self, PeerNode, RemoteAddress="") -> str:
        if len(RemoteAddress) == 0:
            RemoteAddress = PeerNode.IP
        if PeerNode.isNat == True:
            RemoteAddress = '['+PeerNode.natSetting['linkLocalv6']+']'
        if self.IPv6Disable == True:
            ipv6setup=""
        else:
            ipv6setup=";ip addr add "+self.ipv6()+"/128"+" peer " + PeerNode.ipv6()+"/128" + " dev %i"
        CfgInfo="\
[Interface]\n\
PrivateKey = " + self.PrivateKey_Value['base64'] + "\n\
Table = off\n\
PostUp = \
ip addr add " + self.ipv4()+"/32" + " peer " + PeerNode.ipv4()+"/32"+" dev %i "+ipv6setup+"\n\
ListenPort = " + PeerNode.port() + "\n\
MTU = 1420\n\
\n\
[Peer]\n\
PublicKey = " + PeerNode.PublicKey_Value['base64'] + "\n\
AllowedIPs = 0.0.0.0/0,::/0\n\
Endpoint = " + RemoteAddress + ":" + self.port()
        result={
            "Peer" : PeerNode.CoreID ,
            "Config" : CfgInfo
        }
        return(result)

    def wgConfigout(self, PeerInfo, Configfile):
        config = Configfile
        if len(Configfile) == 0:
            config = PeerInfo.CoreID+".conf"
        with open(config,'w') as SelfConfigfile:
            SelfConfigfile.write(self.wgConfig(PeerInfo,PeerInfo.IP)['Config'])
    
    def asn(self, asn_in="", asnprefix="000"):
        if (not self.asn_Value) & (not asn_in):
            self.asn_Value="42"+asnprefix+self.port()
            return("42"+asnprefix+self.port())
        elif asn_in:
            self.asn_Value=asn_in    
        return(self.asn_Value)
    
    def frrConfig(self, routerid, peerlist, net4list , net6list, asnprefix="000"):
        selfasn=self.asn()
        neighbor_cfg=""
        net4_cfg=""
        net6_cfg=""
        for i in peerlist:
            if i.CoreID != self.CoreID:
                neighbor_cfg=neighbor_cfg+" neighbor "+i.ipv4()+" peer-group fabric\n"
        for i in net4list:
            net4_cfg=net4_cfg+"  network "+i+"\n"
        for i in net6list:
            net6_cfg=net6_cfg+"  network "+i+"\n"
        frrConfigContent = "\
router bgp "+selfasn+"\n\
 bgp router-id "+routerid+"\n\
 no bgp ebgp-requires-policy\n\
 neighbor fabric peer-group\n\
 neighbor fabric remote-as external\n\
 neighbor fabric bfd\n"+neighbor_cfg+"\
 address-family ipv4 unicast\n"+net4_cfg+"\
 exit-address-family\n\
 address-family ipv6 unicast\n\
  neighbor fabric activate\n"+net6_cfg+"\
 exit-address-family\n\
 address-family l2vpn evpn\n\
  neighbor fabric activate\n\
  advertise-all-vni\n\
 exit-address-family"
        return(frrConfigContent)

    def frrConfigout(self,router_id,peers,net4,net6, Configfile=""):
        config = Configfile
        configcontent = self.frrConfig(router_id,peers,net4,net6)
        if len(Configfile) == 0:
            config = self.CoreID+".frr.conf"
        with open(config,'w') as SelfConfigfile:
            SelfConfigfile.write(configcontent)
            return(configcontent)

if __name__ == "__main__":
    main(sys.argv[1:])
    pass