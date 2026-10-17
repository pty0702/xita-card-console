#requires -Version 7.0
[CmdletBinding()]
param([string]$OutputPath = 'artifacts/test-payload/XitaTestStub.exe')

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$artifactRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot 'artifacts'))
$targetPath = [IO.Path]::GetFullPath($(if ([IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath
} else {
    Join-Path $projectRoot $OutputPath
}))
if (-not $targetPath.StartsWith($artifactRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetExtension($targetPath) -ine '.exe') {
    throw '测试载荷只能输出到本项目 artifacts 目录内的 .exe 文件。'
}
for ($parentPath = $targetPath; $parentPath.Length -ge $artifactRoot.Length; $parentPath = Split-Path -Parent $parentPath) {
    if ((Test-Path -LiteralPath $parentPath) -and
        ((Get-Item -LiteralPath $parentPath).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw '测试载荷输出目录不能经过符号链接或目录联接。'
    }
}

$compiler = @('Framework64', 'Framework') | ForEach-Object {
    Join-Path $env:WINDIR "Microsoft.NET/$_/v4.0.30319/csc.exe"
} | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $compiler) {
    throw '未找到 Windows .NET Framework v4 编译器 csc.exe。'
}

$null = New-Item -ItemType Directory -Path (Split-Path -Parent $targetPath) -Force
& $compiler /nologo /target:winexe /optimize+ "/out:$targetPath" (Join-Path $PSScriptRoot 'test_payload_stub.cs')
if ($LASTEXITCODE -ne 0) {
    throw "测试载荷编译失败，退出码：$LASTEXITCODE"
}
[pscustomobject]@{
    Path = $targetPath
    Compiler = $compiler
    SHA256 = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash
}
