# 西塔卡密管理与授权系统

包含卡密管理后台、TCP 授权服务、客户端壳与协议测试工具。

## 当前功能

- Web 管理后台：生成时间卡、永久卡与点数卡，搜索、状态筛选、续期、解绑、封禁、批量操作、日志及 CSV 导出。
- 授权校验：设备绑定、到期检查、点数扣减；HTTP 与 TCP 校验使用同一卡库和写事务。
- 通信：TLS、证书指纹校验、服务器 Ed25519 回包签名、请求挑战值与时间戳校验。
- 客户端：在线验证、包含卡种的 SIG2 签名授权缓存、加密程序体启动；点数卡仅允许在线使用。

## 首次准备

已有部署请保留原配置、证书和密钥。本仓库不包含真实传输密钥、服务器私钥、账号、卡库或授权缓存。

1. 将 common/config.example.py 复制为 common/config.py。
2. 在本机环境变量 XITA_TRANSPORT_KEY_HEX 中提供至少 32 字节的十六进制传输密钥；服务端与客户端必须一致。
3. 全新部署运行 python tools/gen_keys.py --host 服务器IP，生成服务器签名密钥及 TLS 证书，并填写本机配置中的公钥与证书指纹。该命令用于初始化，会生成新密钥，已有系统需单独安排密钥迁移。
4. 服务器保管 keys/server_ed25519.key、server.key 与 server.crt；客户端只需要验签公钥、证书指纹及兼容的通信配置。

Python 业务代码使用标准库。生成 TLS 证书需要 OpenSSL，Git for Windows 可提供。Windows 静默测试程序使用 PowerShell 7 与系统 .NET Framework v4 编译器构建。

## 安全升级与旧缓存

本项目沿用已有本地时间凭证模式（LICENSE_INTEGRATION_MODE=time-credential）。SIG2 签名绑定卡号、设备、到期时间和卡种；客户端拒绝 SIG1、HMA1 和无魔数旧缓存，旧缓存需要重新在线验证。点数卡每次启动必须在线扣点，不签发或保留离线授权。

服务端与客户端必须配套升级：先更新服务端，再分发重新打包的客户端，沿用现有密钥和证书。旧客户端及旧 EXE 不会因源码更新而自动获得修复。

启用 TLS 时，客户端要求配置有效的 64 位十六进制证书指纹；缺失、格式错误或指纹不匹配均拒绝连接。服务端在工作线程中握手，握手超时为 10 秒。USE_TLS=False 和 --no-tls 仅用于显式关闭 TLS 的本机开发。

本次未增加可信时钟或在线租约；离线时间卡到期仍依赖本机时间检查，不保证抵御系统时钟回拨，也不能实时获知后台封禁或解绑。

## 启动

在项目根目录执行：

~~~powershell
python admin/admin_web.py --host 127.0.0.1 --port 8080
python server/vps_server.py --host 127.0.0.1 --port 9000
~~~

后台默认地址为 http://127.0.0.1:8080 。首次登录后在设置页修改管理密码。
客户端服务器地址通过同目录 server.ini 或 FJ_HOST / FJ_PORT 环境变量设置。

## 安全回归检查

~~~powershell
python tools/test_admin_ui.py
python common/ed25519.py
python tools/test_signed_protocol.py
python tools/test_tls_client.py
python tools/test_server_security.py
pwsh -NoProfile -File tools/build_test_payload.ps1
python tools/test_payload.py
~~~

后台测试将配置、卡库和日志放在项目 artifacts 临时目录，不使用现有卡密。
载荷测试使用 Main 直接退出的独立测试程序，无窗口、无外部 MUI 文件；进程清理只针对该次测试创建的 Popen 对象。
测试不会拿 Windows 记事本或远程桌面程序充当载荷。

## 客户端验证与载荷

仅检查授权、不启动被保护程序：

~~~powershell
python client/shell.py --cli --verify-only --card "你的卡密"
python client/shell.py --cli --offline --verify-only
~~~

真正启动被保护程序时使用正常客户端入口。tools/pack.py 只加密输入的单个 EXE，不收集资源、DLL 或语言包；依赖旁边文件的程序需要另外设计完整的资源分发，不能只把系统 EXE 改名复制运行。

现有客户端演示载荷已替换为静默测试程序，用于授权与启动流程验证。真实业务交付前应换成你的独立程序；不要把演示载荷当成业务功能。

## 仓库范围

- common/config.py、keys/、数据库、日志、license.dat、生成 EXE 与演示包均留在本机，不提交 Git。
- common/config.example.py 提供首次配置模板；common/crypto.py 和 common/ed25519.py 提供签名协议依赖。
- 管理后台支持的批量动作限定为封禁、解封、解绑、重置、删除与续期 30/365 天，同一请求会去重卡号。
