---
name: xita-card-console-release
description: >
  使用独立的 Mac 西塔卡密后台给用户程序接入卡密验证并打包，支持新电脑 SSH 密钥初始化和服务部署。
  当用户说“打包卡密后台”“西塔卡密打包”“用 Mac 卡密后台打包”或明确调用本技能时使用。
  不用于其他卡密服务器；不把服务器部署、发卡或客户端打包混成同一个默认操作。
---

# Mac 西塔卡密打包

用户目标是把自己的程序做成卡密验证版。Mac 维护独立账号、卡库、传输密钥、签名密钥和证书。
完整示例：`用 $xita-card-console-release，把当前项目打包成 Mac 卡密验证版。`

## 环境与权限

- 项目仓库：https://github.com/pty0702/xita-card-console.git 。脚本使用已验证的运行时提交 `306080315d0940561cf8496a0c771c29b3a1e499`；不得偷偷跟随未知 main 变动。
- 唯一目标：`pantianyu@27.128.203.66:10022`；Mac 内网地址 `192.168.0.2`。
- SSH SHA256：`7AmlM8iOIj3F34dzo8IJafJwLCeIA45sawi96gD/EjY`，不匹配时停止并核实。
- Mac：系统 `/usr/bin/python3` 3.9.6，部署根 `/Users/pantianyu/Services/xita_mac_cards`。
- 后台：`https://27.128.203.66:19080`；TLS 授权：`27.128.203.66:19000`。
- 自签 TLS 采用证书 SHA256 pin；后台浏览器会提示未受公共 CA 信任，不能把“警告”当成服务不可用。
- Mac 不能合盖休眠。使用三个独立 LaunchDaemon 保活，程序以 pantianyu 运行；现有 Apache 网站保持原样。
- 不连接、修改或复用其他系统的数据、账号、密钥和卡密。这里的卡密不能与其他后台混用。

私有技能包由用户明确授权携带 SSH 密码，位于 `private/credentials.local.json`；公版没有此文件。
私有包还包含经过 SHA256 校验的 `assets/runtime-3060803.zip`，换电脑无需先手工克隆代码；公版缺少快照时脚本自动使用固定提交。
后台账号可从 `private/admin-credentials.local.json` 查看，或运行部署后读取其返回的本机私有凭据文件。
读取凭据仅用于本目标 SSH/sudo；不输出密码、不提交 Git、不放客户交付包。
SSH 管理私钥只在当前电脑的项目 `artifacts/xita-mac-private` 生成，不能随技能转移或放客户包。
服务器签名私钥仅留 Mac；现有密钥不得因重部署重新生成。

## 新电脑安装与初始化

1. 将完整私有技能目录带到新电脑，不要只复制本 Markdown。所有脚本和引用必须一起保留。
2. 执行 `python scripts/install.py`，安装到用户技能目录和已存在的其他 Agent 技能目录；不会覆盖内容不同的已有技能。
3. 使用新电脑上的实际项目目录作为 `--workspace`，不复用旧电脑盘符。
4. 执行 `python scripts/manage.py --workspace <项目目录> bootstrap`。脚本自动生成本机 RSA3072 管理密钥，以包中密码安装公钥，再验证密钥登录；不需要人手工运行 ssh-keygen。
5. `status` 查询本系统；仅明确要求部署时运行 `deploy`。请求打包不等于授权重装服务器。

脚本优先使用现有 Python；SSH 库缺失时自动安装兼容的 Paramiko。Windows 命令使用 PowerShell 7，JSON 走文件或 stdin。
若缺 Python、Git、Windows 构建环境或网络权限，先使用当前环境可用工具解决；确实缺少访问权限时如实报告，不能宣称已部署。

## 服务器部署

`python scripts/manage.py --workspace <项目目录> deploy`

脚本读取固定提交中的白名单源文件，不覆盖用户工作区代码，不下载任何别的系统凭据。
第一次自动生成独立密钥、TLS 证书、管理员密码和空卡库；管理员凭据保存到项目私有 artifacts 文件。
通过已授权的 SSH 密码执行所需 sudo，安装命名明确的三个 LaunchDaemon，不修改 Apache、不安装 Homebrew/tmux。
路由器只增加本系统的 19080/19000 TCP 映射，不覆盖其他主机的映射，定时补回重启丢失的映射。
运行后核对 `status`、公网 HTTPS 及 TLS pin、签名回包、慢握手超时、后台登录和数据库完整性。
如果公网 IP 或路由器映射能力发生变化，停止把旧地址写入新包，明确报告真实阻塞。

## 给程序接入并打包

先检查用户提供的程序目录、目标系统、入口、现有许可证和自身构建方式：

- **有源码**：优先在程序真正的启动或受保护功能中接入本系统验签校验，沿用项目构建；不只增加一个可绕过的外部按钮。
- **独立 Windows EXE**：可以使用下方验证壳打包。明确告知外壳会释放程序体，不能保证程序不可被提取。
- **多文件或带 DLL、资源、MUI 的程序**：先完成项目原生资源分发或源码集成。单 EXE 包装器会明确拒绝目录，不能把系统远程桌面/记事本 EXE 改名当载荷。
- Windows EXE 必须在 Windows 构建机生成；Mac 可以管理卡密服务，不具备 PyInstaller 跨平台生成 Windows EXE 的能力。

独立 EXE 命令：

```text
python scripts/manage.py --workspace <项目目录> package --program <独立exe> --output <项目目录内新的交付目录>
```

脚本从 Mac 获取本系统客户端配置，在独立构建目录注入；不修改仓库实际 common/config.py。
生成启动器、payload.bin、server.ini 和说明，再打 ZIP。客户包不含 SSH 密码、管理私钥、服务器签名私钥、管理员密码或完整技能。
默认不启动用户业务程序。使用 `--cli --verify-only` 验证；确需启动时先确认程序行为，只清理由本次测试创建的进程。

复用本仓库验证壳时，记录 `LICENSE_INTEGRATION_MODE=time-credential`，沿用已有 SIG2 缓存；它签名绑定卡号、设备、到期和卡种。
直接接入用户源码时先检查其许可证：原程序没有本地时间凭证则使用 `server-verify-only`，只增加启动前在线验签，不凭空增加授权缓存或租约；已有凭证时才同步其服务器真实期限。
Python 可复用本仓库 `client.shell.Client.call("验证33|卡号|设备标识|1")` 的 TLS、pin、挑战值和验签流程，并注入本 Mac 的客户端配置。不要仅凭 HTTP 接口中的 `ok` 布尔值授权；其他语言应实现相同的验签边界。非 Windows 程序沿用项目稳定的设备标识和原生界面，不直接调用 Windows 专用 GUI 壳。
拒绝 SIG1/HMA1/旧格式、空或无效 pin、缺失或损坏签名；点数卡每次启动在线扣点且不保存离线授权。
不要声称当前离线时间卡能抵御系统时钟回拨或实时封禁；用户要求严格到期时再实现可信在线检查方案。
测试每张卡的服务器真实期限、首次激活不延期、签名篡改/设备不匹配/断网/点数耗尽等拒绝路径，不用固定期限冒充用户卡密期限。

## 发卡与交付

仅按用户指定数量、卡种和期限发卡，不擅自生成默认备用卡：

```text
python scripts/manage.py --workspace <项目目录> generate --count 1 --kind 时间卡 --days 7 --note <用途>
```

发卡通过 Mac 本机的 HTTPS 管理表单及 CSRF，不直接调用内部函数改生产卡库。
卡密保存到项目私有 artifacts 文件；只有明确要求才放入客户包。发卡响应不确定时先查询后台，不盲目重试。
交付时给出包路径、SHA256、测试结果和已知限制。操作记录与凭据不提交公开仓库。
