#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""便携入口：初始化 SSH、部署 Mac、查询、发卡和构建独立 EXE 验证壳。"""
import argparse
import base64
import getpass
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import time
import types
import zipfile

SKILL = Path(__file__).resolve().parents[1]
COMMIT = "306080315d0940561cf8496a0c771c29b3a1e499"
RUNTIME_SHA256 = "6a160e22102e01e0b2a8da093a4838fd004dc3026ce583bc8db7d2205425250e"
REPO = "https://github.com/pty0702/xita-card-console.git"
REMOTE = "/Users/pantianyu/Services/xita_mac_cards"
HOST, SSH_PORT, USER = "27.128.203.66", 10022, "pantianyu"
HOST_PIN = "7AmlM8iOIj3F34dzo8IJafJwLCeIA45sawi96gD/EjY"


def private_file(path):
    if os.name == "nt":
        owner = os.environ.get("USERDOMAIN", "") + "\\" + getpass.getuser()
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", owner+":(F)"],
                       check=True, capture_output=True)
    else:
        path.chmod(0o600)


def write_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    private_file(path)


def paramiko_module():
    try:
        import paramiko
    except ImportError:
        subprocess.run([sys.executable,"-m","pip","install","--user","paramiko>=3.5,<4"],check=True)
        import paramiko
    return paramiko


class Manager:
    def __init__(self, workspace, credentials):
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.state = self.workspace / "artifacts" / "xita-mac-private"
        self.state.mkdir(parents=True, exist_ok=True)
        self.credentials = json.loads(Path(credentials).read_text(encoding="utf-8-sig"))
        private_file(Path(credentials).resolve())
        self.key = self.state / "management_rsa"
        self.paramiko = paramiko_module()

    def connect(self, password_only=False):
        paramiko = self.paramiko
        class PinnedHost(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                got=base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
                if got != HOST_PIN:
                    raise RuntimeError("Mac SSH 主机指纹变化，停止操作并核实身份")
        client=paramiko.SSHClient();client.set_missing_host_key_policy(PinnedHost())
        options={"hostname":HOST,"port":SSH_PORT,"username":USER,"timeout":12,"auth_timeout":12,
                 "banner_timeout":12,"look_for_keys":False,"allow_agent":False}
        if self.key.exists() and not password_only:
            options["pkey"]=paramiko.RSAKey.from_private_key_file(str(self.key))
        else:
            options["password"]=self.credentials["ssh_password"]
        client.connect(**options)
        return client

    def execute(self, command, data="", password_only=False, timeout=45):
        with self.connect(password_only) as client:
            stdin,stdout,stderr=client.exec_command(command,timeout=15)
            stdin.write(data);stdin.flush();stdin.close()
            channel=stdout.channel;out=bytearray();err=bytearray();deadline=time.monotonic()+timeout
            while True:
                while channel.recv_ready():out.extend(channel.recv(65536))
                while channel.recv_stderr_ready():err.extend(channel.recv_stderr(65536))
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():break
                if time.monotonic()>deadline:
                    channel.close();raise TimeoutError("远程操作超时；先查询状态，不盲目重复写操作")
                time.sleep(.02)
            if channel.recv_exit_status()!=0:
                raise RuntimeError(err.decode("utf-8","replace")[-3000:] or "远程操作失败")
            return out.decode("utf-8","replace")

    def bootstrap(self):
        if self.key.exists():
            try:
                self.execute("/usr/bin/true")
                return {"ssh_key_installed":True,"private_key":str(self.key)}
            except self.paramiko.AuthenticationException:
                pass
        if not self.key.exists():
            key=self.paramiko.RSAKey.generate(3072)
            key.write_private_key_file(str(self.key));private_file(self.key)
        key=self.paramiko.RSAKey.from_private_key_file(str(self.key))
        public=key.get_name()+" "+key.get_base64()+" xita-mac-skill"
        script=('from pathlib import Path\nimport os,json\n'
                'folder=Path.home()/".ssh";folder.mkdir(mode=0o700,exist_ok=True);folder.chmod(0o700)\n'
                'target=folder/"authorized_keys"\n'
                'line=%r\nold=target.read_text() if target.exists() else ""\n'
                'if line.split()[1] not in old.split():\n'
                ' with target.open("a") as f:f.write(("" if not old or old.endswith("\\n") else "\\n")+line+"\\n")\n'
                'target.chmod(0o600)\nprint(json.dumps({"installed":True}))\n') % public
        output=self.execute("/usr/bin/python3 -",script,password_only=True)
        self.execute("/usr/bin/true")
        return {"ssh_key_installed":True,"private_key":str(self.key)}

    def runtime(self, action, **fields):
        script=(SKILL/"scripts/mac_runtime.py").read_bytes()
        encoded=base64.b64encode(script).decode()
        command="/usr/bin/python3 -c 'import base64;exec(compile(base64.b64decode(\"%s\"),\"mac_runtime.py\",\"exec\"))'" % encoded
        return json.loads(self.execute(command,json.dumps(dict(action=action,**fields)),timeout=55))

    def repository(self):
        probe=subprocess.run(["git","-C",str(self.workspace),"cat-file","-e",COMMIT+":server/vps_server.py"],capture_output=True)
        if probe.returncode==0:
            return self.workspace
        target=self.workspace/"artifacts"/"xita-card-runtime"
        if not (target/".git").exists():
            args=["git","clone","--no-checkout",REPO,str(target)]
            first=subprocess.run(args,capture_output=True)
            if first.returncode:
                subprocess.run(["git","-c","http.proxy=http://127.0.0.1:10808",
                    "-c","https.proxy=http://127.0.0.1:10808"]+args[1:],check=True)
        return target

    def sources(self):
        archive=SKILL/"assets/runtime-3060803.zip"
        if archive.exists():
            if hashlib.sha256(archive.read_bytes()).hexdigest()!=RUNTIME_SHA256:
                raise RuntimeError("技能中的运行时快照校验失败，拒绝使用")
            with zipfile.ZipFile(archive) as z:
                names=z.namelist()
                if any(Path(n).is_absolute() or ".." in Path(n).parts or
                       not n.startswith(("admin/","server/","common/","client/")) for n in names):
                    raise RuntimeError("运行时快照路径不合法")
                return {n:z.read(n) for n in names}
        repo=self.repository()
        names=subprocess.check_output(["git","-C",str(repo),"ls-tree","-r","--name-only",COMMIT],text=True).splitlines()
        chosen=[n for n in names if n.startswith(("admin/","server/","common/","client/"))
                and n.endswith((".py",".css",".js")) and n!="common/config.example.py"]
        return {n:subprocess.check_output(["git","-C",str(repo),"show",COMMIT+":"+n]) for n in chosen}

    def deploy(self):
        self.bootstrap()
        files={n:base64.b64encode(v).decode() for n,v in self.sources().items()}
        result=self.runtime("deploy",files=files,commit=COMMIT,
            runtime_script=(SKILL/"scripts/mac_runtime.py").read_text(encoding="utf-8-sig"))
        installed=self.execute("sudo -S -p '' /usr/bin/python3 "+REMOTE+"/ops/install_launchd.py",
                               self.credentials["ssh_password"]+"\n")
        private=self.runtime("credentials")
        write_private(self.state/"admin-credentials.json",private)
        result["launchd"]=json.loads(installed)
        result["private_credentials_file"]=str(self.state/"admin-credentials.json")
        deadline=time.monotonic()+15
        while True:
            try:
                result["health"]=self.status();break
            except (OSError,RuntimeError):
                if time.monotonic()>deadline:raise
                time.sleep(.5)
        return result

    def status(self):
        result=self.runtime("status")
        if not all(result["services"][label]["running"] for label in (
                "com.xita.mac-cards.admin","com.xita.mac-cards.license")):
            raise RuntimeError("卡密服务未运行，请检查 Mac 专用日志")
        profile=self.runtime("client-config")
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
        context.minimum_version=ssl.TLSVersion.TLSv1_2
        web=http.client.HTTPSConnection(HOST,19080,context=context,timeout=8)
        web.connect()
        if hashlib.sha256(web.sock.getpeercert(binary_form=True)).hexdigest()!=profile["certificate_pin"]:
            web.close();raise RuntimeError("公网后台证书指纹不匹配")
        web.request("GET","/login");response=web.getresponse();response.read()
        if response.status!=200:
            web.close();raise RuntimeError("公网后台状态异常")
        web.close()
        sources=self.sources()
        package=types.ModuleType("_xita_probe");package.__path__=[];sys.modules[package.__name__]=package
        for name in ("ed25519","crypto"):
            module=types.ModuleType(package.__name__+"."+name);module.__package__=package.__name__
            sys.modules[module.__name__]=module;setattr(package,name,module)
            exec(compile(sources["common/"+name+".py"],name+".py","exec"),module.__dict__)
        crypto=package.crypto
        with socket.create_connection((HOST,19000),timeout=8) as raw:
            with context.wrap_socket(raw,server_hostname=HOST) as secured:
                if hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest()!=profile["certificate_pin"]:
                    raise RuntimeError("公网授权证书指纹不匹配")
                challenge=crypto.new_challenge()
                text=crypto.with_challenge("返回服务器文件|公告.txt",challenge)
                key=bytes.fromhex(profile["transport_key_hex"])
                secured.sendall(crypto.pack_request(666,crypto.seal(key,text.encode("gbk"))))
                def exact(n):
                    data=b""
                    while len(data)<n:
                        chunk=secured.recv(n-len(data))
                        if not chunk:raise RuntimeError("授权连接提前关闭")
                        data+=chunk
                    return data
                header=exact(10)
                if header[:6]!=crypto.MAGIC:raise RuntimeError("授权回包魔数无效")
                length=int.from_bytes(header[6:10],"little")
                if not 10<=length<=1048576:raise RuntimeError("授权回包长度无效")
                text,valid,reason=crypto.open_reply(bytes.fromhex(profile["public_key_hex"]),
                    crypto.unseal(key,exact(length-10)),challenge,60)
                if not valid:raise RuntimeError(reason)
                result["public_tls_version"]=secured.version()
        result.update({"public_admin_https":True,"public_signed_reply":True})
        return result

    def package(self, program, output):
        if os.name!="nt":
            raise RuntimeError("Windows EXE 需要 Windows 构建环境；Mac 可管理服务器，不能用 PyInstaller 跨平台生成 Windows EXE")
        program=Path(program).resolve()
        if not program.is_file() or program.suffix.lower()!=".exe":
            raise ValueError("当前壳仅接受独立 EXE；多文件程序应先按项目自身构建流程做完整资源打包")
        output=Path(output).resolve()
        if os.path.commonpath([str(output),str(self.workspace)])!=str(self.workspace):
            raise ValueError("交付目录必须位于当前项目工作区内")
        if output.exists():raise ValueError("交付目录已存在，请使用新的输出目录")
        output.mkdir(parents=True)
        build=self.state/("build-"+str(time.time_ns()));build.mkdir()
        sources=self.sources()
        for name,data in sources.items():
            if name.startswith(("client/","common/")):
                target=build/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        profile=self.runtime("client-config")
        conf=('KEY=bytes.fromhex(%r)\nPUBLIC_KEY_HEX=%r\nCERT_SHA256=%r\nUSE_TLS=True\n'
              'TS_WINDOW=60\nPORT=%s\nCARD_LEN=32\n') % (profile["transport_key_hex"],profile["public_key_hex"],
                profile["certificate_pin"],profile["license_port"])
        (build/"common/config.py").write_text(conf,encoding="utf-8")
        # 使用隔离子进程加密，避免把其他项目的 common 模块混入当前解释器。
        encrypt=('import sys;sys.path.insert(0,sys.argv[1]);from common import crypto,config;'
                 'from pathlib import Path;Path(sys.argv[3]).write_bytes(b"FJPK"+crypto.seal(config.KEY,Path(sys.argv[2]).read_bytes()))')
        subprocess.run([sys.executable,"-c",encrypt,str(build),str(program),str(output/"payload.bin")],check=True)
        if importlib.util.find_spec("PyInstaller") is None:
            subprocess.run([sys.executable,"-m","pip","install","--user","pyinstaller"],check=True)
        environment=dict(os.environ,PYINSTALLER_CONFIG_DIR=str(build/"pyinstaller-cache"))
        subprocess.run([sys.executable,"-m","PyInstaller","--noconfirm","--clean","--onefile","--windowed",
            "--name","卡密启动器","--paths",str(build),"--distpath",str(output),"--workpath",str(build/"work"),
            "--specpath",str(build),str(build/"client/shell.py")],check=True,cwd=str(build),env=environment)
        (output/"server.ini").write_text("host=%s\nport=%s\n" % (HOST,LICENSE_PORT_LOCAL),encoding="utf-8")
        (output/"使用说明.txt").write_text("运行卡密启动器.exe，输入此 Mac 后台生成的卡密。三个文件必须保持在同一目录。\n"
            "点数卡每次启动联网扣点，旧系统卡密不可用于本系统。\n",encoding="utf-8-sig")
        allowed={"卡密启动器.exe","payload.bin","server.ini","使用说明.txt"}
        if {p.name for p in output.iterdir()} != allowed:raise RuntimeError("交付目录包含非预期文件，未生成 ZIP")
        archive=output.with_suffix(".zip")
        if archive.exists():raise ValueError("ZIP 已存在，拒绝覆盖")
        with zipfile.ZipFile(archive,"w",zipfile.ZIP_DEFLATED) as z:
            for path in sorted(output.iterdir()):z.write(path,path.name)
        return {"package":str(archive),"sha256":hashlib.sha256(archive.read_bytes()).hexdigest(),
                "client_requires_mac_cards":True,"payload_started":False}


LICENSE_PORT_LOCAL=19000


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace",required=True,help="本机项目目录，全部产物存放在其 artifacts 下")
    parser.add_argument("--credentials",default=str(SKILL/"private/credentials.local.json"))
    sub=parser.add_subparsers(dest="action",required=True)
    for name in ("bootstrap","deploy","status"):sub.add_parser(name)
    generate=sub.add_parser("generate");generate.add_argument("--count",type=int,required=True)
    generate.add_argument("--kind",choices=["时间卡","永久卡","点数卡"],required=True)
    generate.add_argument("--days",type=int,default=0);generate.add_argument("--points",type=int,default=0)
    generate.add_argument("--note",default="")
    package=sub.add_parser("package");package.add_argument("--program",required=True);package.add_argument("--output",required=True)
    args=parser.parse_args();manager=Manager(args.workspace,args.credentials)
    if args.action=="bootstrap":result=manager.bootstrap()
    elif args.action=="deploy":result=manager.deploy()
    elif args.action=="status":result=manager.status()
    elif args.action=="generate":
        if not 1<=args.count<=500:raise ValueError("数量须为 1–500")
        result=manager.runtime("generate",count=args.count,kind=args.kind,days=args.days,points=args.points,note=args.note)
        target=manager.state/("cards-"+str(time.time_ns())+".json");write_private(target,result)
        result={"cards_file":str(target),"count":len(result["cards"])}
    else:result=manager.package(args.program,args.output)
    print(json.dumps(result,ensure_ascii=False,indent=2))


if __name__=="__main__":main()
