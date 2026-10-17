#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""安装完整技能目录；已安装版本存在不同文件时停止，不覆盖用户修改。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import getpass

NAME = "xita-card-console-release"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install(source, home):
    roots = [home/".agents/skills"] + [p for p in (
        home/".codex/skills",home/".claude/skills",home/".config/opencode/skills",home/".opencode/skills"
    ) if p.is_dir()]
    files = [p for p in source.rglob("*") if p.is_file() and "__pycache__" not in p.parts
             and not p.name.endswith((".pyc",".pem")) and "state" not in p.relative_to(source).parts]
    outputs=[]
    for root in roots:
        target=root/NAME
        if target.resolve()==source.resolve():
            outputs.append(str(target));continue
        # 先核对整个目标，再写任何文件，避免半安装覆盖。
        for src in files:
            dst=target/src.relative_to(source)
            if dst.exists() and digest(src)!=digest(dst):
                raise RuntimeError("已有技能内容不同，保留原文件，请明确选择更新：%s" % dst)
        for src in files:
            dst=target/src.relative_to(source);dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(src,dst)
            if "private" in src.relative_to(source).parts:
                if os.name=="nt":
                    owner=os.environ.get("USERDOMAIN","")+"\\"+getpass.getuser()
                    subprocess.run(["icacls",str(dst),"/inheritance:r","/grant:r",owner+":(F)"],check=True,capture_output=True)
                else:dst.chmod(0o600)
            if digest(src)!=digest(dst):raise RuntimeError("技能安装文件校验失败：%s" % dst)
        outputs.append(str(target))
    return outputs


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home",type=Path,default=Path.home(),help="用于隔离验证或指定目标用户目录")
    args=parser.parse_args()
    print(json.dumps({"installed":install(Path(__file__).resolve().parents[1],args.home.resolve())},ensure_ascii=False,indent=2))
