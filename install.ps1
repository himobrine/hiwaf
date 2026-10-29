#requires -Version 5.1
<#
.SYNOPSIS
  WAF 控制台一键安装（Windows）。

.DESCRIPTION
  默认控制台优先：Python 3.10 + venv + service 依赖 + 前端构建 + DB/admin 初始化。
  缺 Python/Node 时默认用 winget 自动安装；Rust/采集器只在 -WithRust / -Full 时构建。
  详细说明见仓库根目录 INSTALL.md。

.EXAMPLE
  .\install.bat -NoRust -NoStart
  .\install.bat -Verify
  .\install.bat -WithRust -Port 8091
#>
[CmdletBinding()]
param(
    [int]$Port = 8090,
    [string]$BindHost = "127.0.0.1",
    [switch]$NoVenv,
    [switch]$WithTraining,
    [switch]$NoFrontend,
    [switch]$NoRust,
    [switch]$WithRust,
    [switch]$Full,
    [switch]$NoStart,
    [switch]$Verify,
    [switch]$Systemd,
    [switch]$NoInstallDeps,
    [string]$PipIndex = "",
    [string]$NpmRegistry = "",
    [switch]$DryRun,
    [switch]$Force,
    [switch]$Help,
    [switch]$NoElevate
)

$ErrorActionPreference = "Stop"
$script:ScriptPath = $PSCommandPath
$script:ScriptParams = $PSBoundParameters
$script:Root = Split-Path -Parent $PSCommandPath
$script:PyExe = $null
$script:NodeExe = $null
$script:NpmExe = $null
$script:VenvPy = $null

try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
# Python writes UTF-8 even when stdout is a pipe (PowerShell captures native output).
$env:PYTHONIOENCODING = "utf-8"

function Write-Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message) { Write-Host "[ok] $Message" -ForegroundColor Green }
function Write-Warn([string]$Message) { Write-Host "[warn] $Message" -ForegroundColor Yellow }
function Write-Err([string]$Message) { Write-Host "[x] $Message" -ForegroundColor Red }

function Show-Usage {
    @"
WAF 控制台一键安装（Windows）

用法：
  install.bat [参数]
  powershell -ExecutionPolicy Bypass -File install.ps1 [参数]

常用参数：
  -Port 8090            控制台端口（默认 8090）
  -BindHost 127.0.0.1   监听地址（默认 127.0.0.1；0.0.0.0 会暴露到网络）
  -NoVenv               不创建 .venv，直接用当前 Python 3.10
  -WithTraining         额外安装训练依赖 requirements.txt（体积大）
  -NoFrontend           不构建前端，复用已有 web\dist
  -NoRust               跳过 Rust/采集器构建（默认尽力构建）
  -WithRust             强制安装工具链并构建 Rust/采集器
  -Full                 等价于 -WithRust，且构建失败即退出
  -NoStart              只安装，不启动服务
  -Verify               安装后临时启动并跑 service.smoke
  -NoInstallDeps        缺依赖时只提示，不自动安装
  -PipIndex URL         pip 镜像（例如 https://pypi.tuna.tsinghua.edu.cn/simple）
  -NpmRegistry URL      npm 镜像
  -DryRun               只打印将执行的命令，不改文件
  -Force                跳过非关键检查（不会覆盖 DB/密码）

示例：
  install.bat -NoRust -NoStart
  install.bat -Verify
  install.bat -WithRust -Port 8091
"@ | Write-Host
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-Elevated {
    if ($NoElevate) {
        throw "需要管理员权限安装依赖。请右键「以管理员身份运行」install.bat，或加 -NoInstallDeps 手动安装。"
    }
    Write-Warn "需要管理员权限安装系统依赖，正在请求 UAC ..."
    $forward = @()
    foreach ($key in $script:ScriptParams.Keys) {
        if ($key -eq "NoElevate") { continue }
        $value = $script:ScriptParams[$key]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) { $forward += "-$key" }
        } else {
            $forward += "-$key"
            $forward += [string]$value
        }
    }
    $quoted = @()
    foreach ($item in $forward) {
        if ($item -match '\s') { $quoted += '"' + $item.Replace('"', '\"') + '"' } else { $quoted += $item }
    }
    $argString = "-NoProfile -ExecutionPolicy Bypass -File `"$script:ScriptPath`" " +
        ($quoted -join " ") + " -NoElevate"
    $proc = Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argString -Wait -PassThru
    exit $proc.ExitCode
}

function Refresh-Path {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $extra = @(
        (Join-Path $env:USERPROFILE ".cargo\bin"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links")
    ) -join ";"
    $env:Path = "$machine;$user;$extra"
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @(),
        [string]$WorkDir = ""
    )
    $display = "$Exe " + ($Arguments -join " ")
    if ($DryRun) {
        Write-Host "[dry-run] $display" -ForegroundColor DarkGray
        return 0
    }
    $old = Get-Location
    if ($WorkDir) { Set-Location -LiteralPath $WorkDir }
    try {
        & $Exe @Arguments | Out-Host
        return $LASTEXITCODE
    } finally {
        if ($WorkDir) { Set-Location $old }
    }
}

function Run {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [string[]]$Arguments = @(),
        [string]$WorkDir = ""
    )
    $rc = Invoke-External -Exe $Exe -Arguments $Arguments -WorkDir $WorkDir
    if ($rc -ne 0) {
        throw "命令失败（exit $rc）：$Exe $($Arguments -join ' ')"
    }
}

function Get-Python310 {
    $candidates = @()
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
    if ($py) {
        try {
            $out = & $py.Source -3.10 -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $out) {
                $candidates += [string]($out | Select-Object -Last 1)
            }
        } catch { }
    }
    foreach ($name in @("python.exe", "python3.exe")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { $candidates += $cmd.Source }
    }
    $candidates += @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\Python310\python.exe"),
        "C:\Python310\python.exe",
        (Join-Path $env:ProgramFiles "Python310\python.exe")
    )
    foreach ($candidate in $candidates) {
        if (-not $candidate) { continue }
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        try {
            $ver = & $candidate -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
            if ($LASTEXITCODE -eq 0 -and ([string]$ver).Trim() -eq "3.10") {
                return $candidate
            }
        } catch { }
    }
    return $null
}

function Get-NodeInfo {
    $nodePath = $null
    $cmd = Get-Command node.exe -ErrorAction SilentlyContinue
    if ($cmd) { $nodePath = $cmd.Source }
    if (-not $nodePath) {
        $fallback = Join-Path $env:ProgramFiles "nodejs\node.exe"
        if (Test-Path -LiteralPath $fallback) { $nodePath = $fallback }
    }
    if (-not $nodePath) { return $null }
    try {
        $raw = (& $nodePath -v 2>$null).Trim()
        $ver = $raw.TrimStart("v")
        $major = [int]($ver.Split(".")[0])
        if ($major -lt 18) { return $null }
    } catch { return $null }

    $npmPath = Join-Path (Split-Path -Parent $nodePath) "npm.cmd"
    if (-not (Test-Path -LiteralPath $npmPath)) {
        $npmCmd = Get-Command npm.cmd -ErrorAction SilentlyContinue
        if ($npmCmd) { $npmPath = $npmCmd.Source } else { return $null }
    }
    return [pscustomobject]@{ Node = $nodePath; Npm = $npmPath; Version = $ver }
}

function Test-VcTools {
    if ($env:VSCMD_ARG_TGT_ARCH) { return $true }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        try {
            $out = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
            if ($LASTEXITCODE -eq 0 -and $out) { return $true }
        } catch { }
    }
    $roots = @(
        "D:\visual_studio",
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\BuildTools"),
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Community"),
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Professional"),
        (Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\Enterprise")
    )
    foreach ($root in $roots) {
        if (Test-Path -LiteralPath (Join-Path $root "VC\Auxiliary\Build\vcvars64.bat")) { return $true }
    }
    return $false
}

function Test-RustToolchain {
    $cargo = Get-Command cargo.exe -ErrorAction SilentlyContinue
    $cmake = Get-Command cmake.exe -ErrorAction SilentlyContinue
    $ninja = Get-Command ninja.exe -ErrorAction SilentlyContinue
    return [bool]($cargo -and $cmake -and $ninja -and (Test-VcTools))
}

function Install-Winget {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [string[]]$Extra = @()
    )
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw "未找到 winget。请先安装 App Installer：https://aka.ms/getwinget"
    }
    $argList = @(
        "install", "--id", $Id, "--exact", "--silent",
        "--accept-package-agreements", "--accept-source-agreements"
    ) + $Extra
    Run -Exe $winget.Source -Arguments $argList
}

function Ensure-BaseDeps {
    $script:PyExe = Get-Python310
    $node = Get-NodeInfo
    $missing = @()
    if (-not $script:PyExe) { $missing += "Python 3.10" }
    if (-not $node) { $missing += "Node.js 18+（含 npm）" }
    if ($missing.Count -eq 0) {
        $script:NodeExe = $node.Node
        $script:NpmExe = $node.Npm
        Write-Ok "Python 3.10: $script:PyExe"
        Write-Ok "Node.js $($node.Version): $($node.Node)"
        return
    }

    Write-Warn ("缺少系统依赖：" + ($missing -join "、"))
    if ($NoInstallDeps) {
        throw "请先手动安装：winget install --id Python.Python.3.10 -e；winget install --id OpenJS.NodeJS.LTS -e（装完重开终端）"
    }
    if ($DryRun) {
        Write-Host "[dry-run] winget install --id Python.Python.3.10 -e"
        Write-Host "[dry-run] winget install --id OpenJS.NodeJS.LTS -e"
        exit 0
    }
    if (-not (Test-Admin)) { Restart-Elevated }

    if (-not $script:PyExe) {
        Write-Step "安装 Python 3.10（winget）"
        Install-Winget -Id "Python.Python.3.10"
        Refresh-Path
        $script:PyExe = Get-Python310
    }
    if (-not $node) {
        Write-Step "安装 Node.js LTS（winget）"
        Install-Winget -Id "OpenJS.NodeJS.LTS"
        Refresh-Path
        $node = Get-NodeInfo
    }
    if (-not $script:PyExe) { throw "Python 3.10 安装后仍未找到；请重开终端或检查 PATH" }
    if (-not $node) { throw "Node.js 安装后仍未找到；请重开终端或检查 PATH" }
    $script:NodeExe = $node.Node
    $script:NpmExe = $node.Npm
    Write-Ok "Python 3.10: $script:PyExe"
    Write-Ok "Node.js $($node.Version): $($node.Node)"
}

function Ensure-RustDeps {
    if (Test-RustToolchain) { return }
    if ($NoInstallDeps) {
        throw "Rust 构建需要 cargo + cmake + ninja + VS C++ 工作负载；请手动安装后重试。"
    }
    if ($DryRun) {
        Write-Host "[dry-run] winget install Rustlang.Rustup / Kitware.CMake / Ninja-build.Ninja / Microsoft.VisualStudio.2022.BuildTools"
        exit 0
    }
    if (-not (Test-Admin)) { Restart-Elevated }
    if (-not (Get-Command cargo.exe -ErrorAction SilentlyContinue)) {
        Write-Step "安装 Rust（winget）"
        Install-Winget -Id "Rustlang.Rustup"
    }
    if (-not (Get-Command cmake.exe -ErrorAction SilentlyContinue)) {
        Write-Step "安装 CMake（winget）"
        Install-Winget -Id "Kitware.CMake"
    }
    if (-not (Get-Command ninja.exe -ErrorAction SilentlyContinue)) {
        Write-Step "安装 Ninja（winget）"
        Install-Winget -Id "Ninja-build.Ninja"
    }
    if (-not (Test-VcTools)) {
        Write-Step "安装 Visual Studio 2022 Build Tools（C++ 工作负载，体积较大）"
        Install-Winget -Id "Microsoft.VisualStudio.2022.BuildTools" -Extra @(
            "--override", "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
        )
    }
    Refresh-Path
    if (-not (Test-RustToolchain)) {
        throw "工具链安装后仍不完整；请重开终端，或安装 VS C++ 工作负载后重试。"
    }
}

function Ensure-PythonDeps {
    $venv = Join-Path $script:Root ".venv"
    if ($NoVenv) {
        $script:VenvPy = $script:PyExe
        Write-Warn "使用当前 Python（-NoVenv）：$script:VenvPy"
    } else {
        $script:VenvPy = Join-Path $venv "Scripts\python.exe"
        if (-not (Test-Path -LiteralPath $script:VenvPy)) {
            Write-Step "创建 venv：$venv"
            Run -Exe $script:PyExe -Arguments @("-m", "venv", $venv)
        }
    }

    Write-Step "安装控制面 Python 依赖"
    $upgrade = @("-m", "pip", "install", "--upgrade", "pip")
    if ($PipIndex) { $upgrade += @("-i", $PipIndex) }
    Run -Exe $script:VenvPy -Arguments $upgrade

    $req = Join-Path $script:Root "python\requirements-service.txt"
    $install = @("-m", "pip", "install", "-r", $req)
    if ($PipIndex) { $install += @("-i", $PipIndex) }
    Run -Exe $script:VenvPy -Arguments $install

    if ($WithTraining) {
        Write-Step "安装训练依赖（体积较大）"
        $trainReq = Join-Path $script:Root "python\requirements.txt"
        $train = @("-m", "pip", "install", "-r", $trainReq)
        if ($PipIndex) { $train += @("-i", $PipIndex) }
        Run -Exe $script:VenvPy -Arguments $train
    }
}

function Ensure-Frontend {
    if ($NoFrontend) {
        Write-Warn "跳过前端构建（-NoFrontend），复用 web\dist"
        return
    }
    $web = Join-Path $script:Root "web"
    Write-Step "构建前端"
    $install = @("ci")
    if ($NpmRegistry) { $install += @("--registry=$NpmRegistry") }
    Run -Exe $script:NpmExe -Arguments $install -WorkDir $web
    Run -Exe $script:NpmExe -Arguments @("run", "typecheck") -WorkDir $web
    Run -Exe $script:NpmExe -Arguments @("run", "build") -WorkDir $web
}

function Invoke-Bootstrap {
    Write-Step "初始化数据库与 admin"
    Run -Exe $script:VenvPy -Arguments @("-m", "service.bootstrap") -WorkDir (Join-Path $script:Root "python")
}

function Get-CargoTarget {
    if ($env:WAF_CARGO_TARGET) { return $env:WAF_CARGO_TARGET }
    if (Test-Path -LiteralPath "E:\") { return "E:\waf-target" }
    return (Join-Path $env:LOCALAPPDATA "waf-cargo-target")
}

function Invoke-RustBuild {
    if ($NoRust -and -not $Full -and -not $WithRust) {
        Write-Warn "跳过 Rust/采集器构建（-NoRust）"
        return
    }
    $want = $WithRust -or $Full
    if (-not (Test-RustToolchain)) {
        if ($want) {
            Ensure-RustDeps
        } else {
            Write-Warn "未找到完整 Rust 工具链，跳过 Rust/采集器构建；需要时用 -WithRust"
            return
        }
    }

    $target = Get-CargoTarget
    $env:WAF_CARGO_TARGET = $target
    $env:CARGO_TARGET_DIR = $target
    Write-Step "构建 Rust 判定引擎（缓存：$target）"
    $rustOk = $true
    $proxyOk = $true
    try {
        Run -Exe "cmd.exe" -Arguments @("/c", "build.bat", "build", "--release") -WorkDir (Join-Path $script:Root "rust")
    } catch {
        if ($Full) { throw }
        $rustOk = $false
        Write-Warn "Rust 引擎构建失败：$($_.Exception.Message)"
    }
    try {
        Write-Step "构建采集器 waf-collector"
        Run -Exe "cmd.exe" -Arguments @("/c", "build.bat", "build", "--release") -WorkDir (Join-Path $script:Root "proxy")
    } catch {
        if ($Full) { throw }
        $proxyOk = $false
        Write-Warn "采集器构建失败：$($_.Exception.Message)"
    }

    $engine = Join-Path $target "release\waf-ai-proto.exe"
    $collector = Join-Path $target "release\waf-collector.exe"
    if ($rustOk -and (Test-Path -LiteralPath $engine)) { Write-Ok "Rust 引擎：$engine" }
    if ($proxyOk -and (Test-Path -LiteralPath $collector)) { Write-Ok "采集器：$collector" }
    if (-not (Test-Path -LiteralPath $collector)) {
        Write-Warn "未找到采集器二进制；控制台「采集代理」页会提示缺失"
    }
}

function Wait-Http {
    param([string]$Url, [int]$TimeoutSec = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
            if ($resp.StatusCode -eq 200) { return $true }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Show-Summary {
    $urlHost = $BindHost
    if ($urlHost -eq "0.0.0.0") { $urlHost = "127.0.0.1" }
    $url = "http://${urlHost}:$Port"
    $py = $script:VenvPy
    $pw = Join-Path $script:Root "python\service\.admin_password"
    Write-Host ""
    Write-Host "安装完成" -ForegroundColor Green
    Write-Host "  控制台     : $url"
    Write-Host "  接口文档   : $url/docs"
    Write-Host "  admin 密码 : $pw（首次生成；已有库不会覆盖）"
    Write-Host "  采集代理   : $url -> 登录后「采集代理」页"
    Write-Host "  启动命令   : cd `"$($script:Root)\python`"; & `"$py`" -m service.run --host $BindHost --port $Port"
}

function Invoke-Start {
    $urlHost = $BindHost
    if ($urlHost -eq "0.0.0.0") { $urlHost = "127.0.0.1" }
    $url = "http://${urlHost}:$Port"

    if ($NoStart) {
        Write-Warn "已跳过启动（-NoStart）"
        return
    }

    if ($Verify) {
        Write-Step "临时启动服务并执行 smoke"
        $logDir = Join-Path $script:Root "python\service\logs"
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
        $outLog = Join-Path $logDir "install-verify.out.log"
        $errLog = Join-Path $logDir "install-verify.err.log"
        $proc = Start-Process -FilePath $script:VenvPy `
            -ArgumentList @("-m", "service.run", "--host", $BindHost, "--port", "$Port") `
            -WorkingDirectory (Join-Path $script:Root "python") `
            -RedirectStandardOutput $outLog -RedirectStandardError $errLog `
            -PassThru -WindowStyle Hidden
        try {
            if (-not (Wait-Http -Url $url -TimeoutSec 60)) {
                throw "服务未在 60s 内就绪；查看 $errLog"
            }
            $env:WAF_CONSOLE_BASE = $url
            Run -Exe $script:VenvPy -Arguments @("-m", "service.smoke") -WorkDir (Join-Path $script:Root "python")
        } finally {
            if ($proc -and -not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force
            }
        }
        Write-Ok "smoke 通过；现在可以正式启动：$url"
        return
    }

    Write-Step "启动控制台：$url（Ctrl+C 停止）"
    Push-Location (Join-Path $script:Root "python")
    try {
        & $script:VenvPy -m service.run --host $BindHost --port $Port
    } finally {
        Pop-Location
    }
}

function Invoke-Main {
    if ($Help) { Show-Usage; return }
    if ($Systemd) { throw "-Systemd 仅 Linux 支持；Windows 请用前台启动或任务计划程序。" }

    foreach ($rel in @("python\service\app.py", "web\package.json", "proxy\Cargo.toml")) {
        if (-not (Test-Path -LiteralPath (Join-Path $script:Root $rel))) {
            throw "仓库不完整：缺少 $rel（脚本应放在仓库根目录）"
        }
    }

    Write-Host "WAF 控制台一键安装（Windows）" -ForegroundColor White
    Write-Host "仓库：$script:Root"
    if ($DryRun) { Write-Warn "dry-run：只打印命令，不执行安装/写入" }

    Ensure-BaseDeps
    Ensure-PythonDeps
    Ensure-Frontend
    Invoke-Bootstrap
    Invoke-RustBuild
    Show-Summary
    Invoke-Start
}

try {
    Invoke-Main
} catch {
    Write-Err $_.Exception.Message
    exit 1
}
