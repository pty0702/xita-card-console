#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""仅在目标 Mac 运行：独立初始化、端口映射和本机管理 API。"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

ROOT = Path.home() / "Services" / "xita_mac_cards"
HOST = "27.128.203.66"
ADMIN_PORT, LICENSE_PORT = 19080, 19000
LABELS = ("com.xita.mac-cards.admin", "com.xita.mac-cards.license", "com.xita.mac-cards.ports")


def save(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    path.chmod(mode)


def management():
    return json.loads((ROOT / "management.json").read_text())


def router_call(action, fields):
    service = "urn:schemas-upnp-org:service:WANIPConnection:1"
    body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:%s xmlns:u="%s">%s'
            '</u:%s></s:Body></s:Envelope>') % (action, service, "".join(
                "<%s>%s</%s>" % (k, escape(str(v)), k) for k, v in fields.items()), action)
    request = urllib.request.Request("http://192.168.0.1:1900/ipc", data=body.encode(), headers={
        "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": '"%s#%s"' % (service, action)})
    try:
        data = urllib.request.urlopen(request, timeout=5).read()
    except urllib.error.HTTPError as exc:
        data = exc.read()
    values = {e.tag.rsplit("}", 1)[-1]: e.text or "" for e in ET.fromstring(data).iter() if not len(e)}
    return values


def map_ports():
    result = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("192.168.0.1", 1900))
        lan = sock.getsockname()[0]
    external = router_call("GetExternalIPAddress", {}).get("NewExternalIPAddress")
    if external != HOST:
        raise RuntimeError("路由器公网 IP 已变化，拒绝向错误目标发布：%s" % external)
    for port in (ADMIN_PORT, LICENSE_PORT):
        query = {"NewRemoteHost": "", "NewExternalPort": port, "NewProtocol": "TCP"}
        current = router_call("GetSpecificPortMappingEntry", query)
        if "NewInternalClient" in current and (
                current["NewInternalClient"] != lan or current.get("NewInternalPort") != str(port)):
            raise RuntimeError("端口 %s 已被其他服务占用，未覆盖" % port)
        added = router_call("AddPortMapping", dict(query, NewInternalPort=port,
            NewInternalClient=lan, NewEnabled=1, NewPortMappingDescription="Xita Mac Cards %s" % port,
            NewLeaseDuration=0))
        if "errorCode" in added:
            raise RuntimeError("端口映射失败：%s" % added)
        confirmed = router_call("GetSpecificPortMappingEntry", query)
        if confirmed.get("NewInternalClient") != lan or confirmed.get("NewInternalPort") != str(port):
            raise RuntimeError("路由器未确认预期端口映射")
        result[str(port)] = {"external": HOST, "internal": lan, "port": port}
    return result


ADMIN_RUNNER = '''import sys,ssl
from pathlib import Path
from http.server import ThreadingHTTPServer
root=Path(__file__).resolve().parent;sys.path.insert(0,str(root))
from admin import admin_web as web
from server.vps_server import build_ssl_context
class SecureAdmin(ThreadingHTTPServer):
    daemon_threads=True
    def finish_request(self,request,address):
        request.settimeout(10)
        try:
            with self.context.wrap_socket(request,server_side=True) as secured:
                self.RequestHandlerClass(secured,address,self)
        except OSError:
            pass
        finally:
            request.close()
web.load_conf();conn=web.db();conn.close()
with SecureAdmin(("0.0.0.0",19080),web.H) as server:
    server.context=build_ssl_context();server.serve_forever()
'''

INSTALL_LAUNCHD = '''import os,plistlib,shutil,subprocess,json
from pathlib import Path
root=Path(%r)
if os.geteuid()!=0:raise RuntimeError('requires sudo')
labels=%r
for label in labels:
    source=root/'ops'/'launchd'/(label+'.plist')
    spec=plistlib.loads(source.read_bytes())
    if spec['Label']!=label or spec['UserName']!='pantianyu':raise RuntimeError('invalid daemon identity')
    target=Path('/Library/LaunchDaemons')/(label+'.plist')
    if target.exists():
        old=plistlib.loads(target.read_bytes())
        if old.get('Label')!=label or old.get('UserName')!='pantianyu' or old.get('WorkingDirectory')!=str(root):
            raise RuntimeError('existing daemon belongs to another deployment')
        backup=root/'backups'/'launchd';backup.mkdir(parents=True,exist_ok=True)
        shutil.copy2(target,backup/(label+'.plist'))
    shutil.copy2(source,target);os.chown(target,0,0);os.chmod(target,0o644)
    subprocess.run(['/bin/launchctl','bootout','system/'+label],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['/bin/launchctl','bootstrap','system',str(target)],check=True)
print(json.dumps({'launchd':list(labels),'installed':True}))
'''


def deploy(payload):
    ROOT.mkdir(parents=True, exist_ok=True)
    ROOT.chmod(0o700)
    marker = ROOT / "identity.json"
    if any(ROOT.iterdir()) and not marker.exists():
        raise RuntimeError("目标目录已有非本技能文件，拒绝覆盖")
    if marker.exists():
        if json.loads(marker.read_text()).get("system") != "xita-mac-independent":
            raise RuntimeError("目标目录系统标识不同，拒绝覆盖")
    save(marker, json.dumps({"system": "xita-mac-independent", "commit": payload["commit"]}))
    stamp = time.strftime("%Y%m%dT%H%M%S")
    backup = ROOT / "backups" / stamp
    if not (ROOT / "common/config.py").exists() and (ROOT / "keys/server_ed25519.key").exists():
        raise RuntimeError("已有密钥但配置缺失，拒绝重新初始化；先恢复配置")
    if (ROOT / "common/config.py").exists():
        for rel in ("common/config.py", "admin/config.json", "management.json"):
            path=ROOT/rel
            if path.exists():
                dst=backup/rel;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,dst)
        if (ROOT/"server/cards.db").exists():
            backup.mkdir(parents=True,exist_ok=True)
            source=sqlite3.connect("file:"+str(ROOT/"server/cards.db")+"?mode=ro",uri=True)
            destination=sqlite3.connect(str(backup/"cards.db"))
            source.backup(destination);destination.close();source.close()
            (backup/"cards.db").chmod(0o600)
    for name, encoded in payload["files"].items():
        rel = Path(name)
        if rel.is_absolute() or ".." in rel.parts or rel.parts[0] not in ("admin", "server", "common", "client"):
            raise ValueError("非法发布路径")
        target = ROOT / rel
        if target.is_file():
            old = backup / rel; old.parent.mkdir(parents=True, exist_ok=True);shutil.copy2(target, old)
        data = base64.b64decode(encoded)
        if name.endswith(".py"):
            compile(data, name, "exec")
        save(target, data)
    (ROOT / "keys").mkdir(exist_ok=True, mode=0o700)
    (ROOT / "logs").mkdir(exist_ok=True, mode=0o700)
    sys.path.insert(0, str(ROOT))
    fresh = not (ROOT / "common/config.py").exists()
    if fresh:
        from common import ed25519
        secret, public = ed25519.gen_keypair()
        save(ROOT / "keys/server_ed25519.key", secret.hex()+"\n")
        save(ROOT / "keys/server_ed25519.pub", public.hex()+"\n")
        cert_config = ('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=xita-mac-cards\n'
                       '[v3]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n'
                       'extendedKeyUsage=serverAuth\nsubjectAltName=IP:%s,IP:192.168.0.2,IP:127.0.0.1\n' % HOST)
        save(ROOT / "keys/openssl.cnf", cert_config)
        subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "3650", "-config", str(ROOT / "keys/openssl.cnf"), "-keyout", str(ROOT / "keys/server.key"),
            "-out", str(ROOT / "keys/server.crt")], check=True, capture_output=True)
        for path in (ROOT / "keys").iterdir():
            path.chmod(0o600)
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert((ROOT / "keys/server.crt").read_text())).hexdigest()
        conf = ('import os\nKEY=bytes.fromhex(%r)\nPORT=19000\nHOST="0.0.0.0"\nPROTO_VER="1"\n'
                'PUBLIC_KEY_HEX=%r\nCERT_SHA256=%r\nUSE_TLS=True\nTS_WINDOW=60\n'
                'BASE=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))\n'
                'DB_PATH=os.path.join(BASE,"server","cards.db")\nPUBLIC_DIR=os.path.join(BASE,"server","public")\n'
                'KEY_DIR=os.path.join(BASE,"keys")\nCARD_PREFIX="MACXIT"\nCARD_LEN=32\n') % (
                    secrets.token_hex(32), public.hex(), pin)
        save(ROOT / "common/config.py", conf)
        password = secrets.token_urlsafe(20)
        salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()
        save(ROOT / "admin/config.json", json.dumps({"site": "西塔 · Mac 卡密管理平台",
            "secret": secrets.token_hex(32), "password_pbkdf2": "pbkdf2_sha256$260000$%s$%s" % (salt, hashed)}, ensure_ascii=False))
        save(ROOT / "management.json", json.dumps({"admin_user": "admin", "admin_password": password,
            "admin_url": "https://%s:%s" % (HOST, ADMIN_PORT), "license_host": HOST,
            "license_port": LICENSE_PORT, "certificate_pin": pin}))
    from server import vps_server
    vps_server.init_db()
    save(ROOT / "admin_tls.py", ADMIN_RUNNER)
    save(ROOT / "ops/mac_runtime.py", payload["runtime_script"])
    save(ROOT / "ops/install_launchd.py", INSTALL_LAUNCHD % (str(ROOT), LABELS))
    programs = (["/usr/bin/python3", "-u", str(ROOT / "admin_tls.py")],
                ["/usr/bin/python3", "-u", str(ROOT / "server/vps_server.py")],
                ["/usr/bin/python3", "-u", str(ROOT / "ops/mac_runtime.py"), "map"])
    for label, program in zip(LABELS, programs):
        spec = {"Label": label, "UserName": "pantianyu", "ProgramArguments": program,
                "WorkingDirectory": str(ROOT), "RunAtLoad": True, "Umask": 63,
                "StandardOutPath": str(ROOT / "logs" / (label+".out.log")),
                "StandardErrorPath": str(ROOT / "logs" / (label+".err.log"))}
        if label.endswith(".ports"):
            spec["StartInterval"] = 300
        else:
            spec["KeepAlive"] = True
        save(ROOT / "ops/launchd" / (label+".plist"), plistlib.dumps(spec))
    mapping = map_ports()
    return {"root": str(ROOT), "fresh": fresh, "mapping": mapping,
            "admin_url": management()["admin_url"], "sudo_installer": str(ROOT / "ops/install_launchd.py")}


def client_config():
    sys.path.insert(0, str(ROOT))
    from common import config
    return {"transport_key_hex": config.KEY.hex(), "public_key_hex": config.PUBLIC_KEY_HEX,
            "certificate_pin": config.CERT_SHA256, "license_host": HOST, "license_port": LICENSE_PORT}


def generate(payload):
    # 走现有 HTTPS 管理表单和 CSRF，不直接写数据库生成卡密。
    cfg = management()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False;context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    cookies = {}
    def request(method, path, fields=None):
        conn = http.client.HTTPSConnection("127.0.0.1", ADMIN_PORT, context=context, timeout=8)
        conn.connect()
        if hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() != cfg["certificate_pin"]:
            conn.close();raise RuntimeError("后台证书指纹不匹配")
        body = urllib.parse.urlencode(fields).encode() if fields is not None else None
        headers = {"Cookie": "; ".join(k+"="+v for k,v in cookies.items())}
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body, headers)
        response = conn.getresponse();text = response.read().decode()
        for key,value in response.getheaders():
            if key.lower()=="set-cookie":
                k,v=value.split(";",1)[0].split("=",1);cookies[k]=v
        status = response.status;conn.close()
        return status,text
    status, text = request("GET", "/login")
    csrf = re.search(r'name="csrf" value="([^"]+)"', text).group(1)
    status,_ = request("POST", "/login", {"user":"admin","pass":cfg["admin_password"],"csrf":csrf})
    if status != 302 or "sess" not in cookies:
        raise RuntimeError("后台登录失败")
    status,text = request("POST", "/new", {"num":payload["count"],"kind":payload["kind"],
        "days":payload.get("days",0),"points":payload.get("points",0),"note":payload.get("note",""),"csrf":csrf})
    if status != 200:
        raise RuntimeError("后台拒绝生成卡密：HTTP %s" % status)
    cards = list(dict.fromkeys(re.findall(r'MACXIT[A-Z0-9]{26}', text)))
    if len(cards) != payload["count"]:
        raise RuntimeError("生成数量与页面结果不一致，先查询后台，禁止自动重试以免重复发卡")
    return {"cards":cards,"kind":payload["kind"]}


def status():
    cfg = management();db=sqlite3.connect("file:"+str(ROOT/"server/cards.db")+"?mode=ro",uri=True)
    count=db.execute("select count(*) from cards").fetchone()[0]
    check=db.execute("pragma quick_check").fetchone()[0];db.close()
    states={}
    for label in LABELS:
        probe=subprocess.run(["/bin/launchctl","print","system/"+label],capture_output=True,text=True)
        states[label]={"loaded":probe.returncode==0,"running":"state = running" in probe.stdout}
    return {"root":str(ROOT),"services":states,"cards":count,"integrity":check,
            "admin_url":cfg["admin_url"],"certificate_pin":cfg["certificate_pin"]}


if __name__ == "__main__":
    payload = {"action":"map"} if len(sys.argv)>1 and sys.argv[1]=="map" else json.load(sys.stdin)
    action = payload["action"]
    if action == "deploy": result=deploy(payload)
    elif action == "map": result=map_ports()
    elif action == "status": result=status()
    elif action == "client-config": result=client_config()
    elif action == "credentials": result=management()
    elif action == "generate": result=generate(payload)
    else: raise ValueError("未知操作")
    print(json.dumps(result,ensure_ascii=True))
