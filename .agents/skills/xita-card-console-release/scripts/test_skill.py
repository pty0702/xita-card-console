#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""隔离验证完整技能安装、拒绝覆盖与路由映射冲突保护，不接触真实服务器。"""
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

SCRIPTS=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location("xita_check_"+name,SCRIPTS/(name+".py"))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def rejects(call):
    try:call()
    except (RuntimeError,ValueError):return
    raise AssertionError("应拒绝不安全操作")


def main():
    installer,runtime,manager_module=load("install"),load("mac_runtime"),load("manage")
    artifacts=SCRIPTS.parents[3]/"artifacts"/"skill-check"
    artifacts.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=artifacts) as folder:
        folder=Path(folder);home=folder/"home";home.mkdir();(home/".claude/skills").mkdir(parents=True)
        source=folder/"source";source.mkdir()
        (source/"SKILL.md").write_text("---\nname: xita-card-console-release\ndescription: check\n---\n",encoding="utf-8")
        (source/"scripts").mkdir();(source/"scripts/helper.py").write_text("pass\n")
        installed=installer.install(source,home);assert len(installed)==2
        assert installer.install(source,home)==installed
        target=Path(installed[0])/"SKILL.md";target.write_text("用户修改",encoding="utf-8")
        rejects(lambda:installer.install(source,home));assert target.read_text(encoding="utf-8")=="用户修改"

        root=folder/"unknown";root.mkdir();(root/"existing.txt").write_text("keep")
        with patch.object(runtime,"ROOT",root):
            rejects(lambda:runtime.deploy({"commit":"test","files":{}}))
            assert (root/"existing.txt").read_text()=="keep"
        class UDP:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def connect(self,address):pass
            def getsockname(self):return ("192.168.0.2",1)
        calls=[];mappings={}
        def router(action,fields):
            calls.append((action,fields))
            if action=="GetExternalIPAddress":return {"NewExternalIPAddress":runtime.HOST}
            port=fields["NewExternalPort"]
            if action=="GetSpecificPortMappingEntry":return mappings.get(port,{"errorCode":"501"})
            if action=="AddPortMapping":
                mappings[port]={"NewInternalClient":fields["NewInternalClient"],"NewInternalPort":str(port)}
                return {}
            raise AssertionError(action)
        with patch.object(runtime.socket,"socket",return_value=UDP()),patch.object(runtime,"router_call",side_effect=router):
            assert len(runtime.map_ports())==2
            mappings[19080]={"NewInternalClient":"192.168.0.99","NewInternalPort":"19080"};calls.clear()
            rejects(runtime.map_ports)
            assert all(action!="AddPortMapping" for action,_ in calls)
        compile(runtime.ADMIN_RUNNER,"admin_tls.py","exec")
        compile(runtime.INSTALL_LAUNCHD % (str(root),runtime.LABELS),"install_launchd.py","exec")
        bundle=folder/"bundle";(bundle/"assets").mkdir(parents=True)
        (bundle/"assets/runtime-3060803.zip").write_bytes(b"tampered")
        manager=manager_module.Manager.__new__(manager_module.Manager)
        with patch.object(manager_module,"SKILL",bundle):
            rejects(manager.sources)
    print("技能隔离检查通过：完整安装、保留修改、拒绝覆盖未知目录、路由映射冲突保护与模板语法。")


if __name__=="__main__":main()
