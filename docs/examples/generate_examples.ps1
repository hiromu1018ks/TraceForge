# generate_examples.ps1 — TraceForge 出力例の自動生成（T8-024・製品 §13.2）
#
# 合成 LNK fixture（[MS-SHLLINK] §2.1 準拠）から各形式の出力例を生成する。
# 手書きの例ではなく、実際の CLI binary 出力を使用する（製品 §13.2）。
#
# 実行: .\docs\examples\generate_examples.ps1

param(
    [string]$RepoRoot = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
)

$ErrorActionPreference = "Stop"
$exDir = Join-Path $RepoRoot "docs\examples"
$tmpDir = Join-Path $env:TEMP "tf_examples"
$null = New-Item -ItemType Directory -Path $tmpDir -Force
$null = New-Item -ItemType Directory -Path $exDir -Force

Write-Host "=== TraceForge 出力例の自動生成 ==="

# 1. 合成 LNK fixture を構築
$lnk = [System.Collections.Generic.List[byte]]::new()
$lnk.AddRange([BitConverter]::GetBytes([uint32]0x4C))                 # HeaderSize
$lnk.AddRange([byte[]](0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))  # CLSID
$lnk.AddRange([BitConverter]::GetBytes([uint32]0x80))                 # flags: IsUnicode
$lnk.AddRange([BitConverter]::GetBytes([uint32]0))                    # FileAttributes
$lnk.AddRange([BitConverter]::GetBytes([uint64]0))                    # CreationTime
$lnk.AddRange([BitConverter]::GetBytes([uint64]0))                    # AccessTime
$lnk.AddRange([BitConverter]::GetBytes([uint64]130605440000000000))   # WriteTime
$lnk.AddRange([BitConverter]::GetBytes([uint32]0))                    # FileSize
$lnk.AddRange([BitConverter]::GetBytes([int32]0))                     # IconIndex
$lnk.AddRange([BitConverter]::GetBytes([uint32]1))                    # ShowCommand
$lnk.AddRange([BitConverter]::GetBytes([uint16]0))                    # HotKey
$lnk.AddRange([BitConverter]::GetBytes([uint16]0))                    # Reserved1
$lnk.AddRange([BitConverter]::GetBytes([uint32]0))                    # Reserved2
$lnk.AddRange([BitConverter]::GetBytes([uint32]0))                    # Reserved3
$lnk.AddRange([BitConverter]::GetBytes([uint32]0))                    # TerminalBlock
$lnkPath = Join-Path $tmpDir "sample.lnk"
[System.IO.File]::WriteAllBytes($lnkPath, $lnk.ToArray())
Write-Host "fixture: $lnkPath ($($lnk.Count) bytes)"

# 2. CLI binary をビルド
Push-Location $RepoRoot
try {
    Write-Host "building tf-cli (release)..."
    cargo build -p tf-cli --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build 失敗" }
} finally {
    Pop-Location
}
$exe = Join-Path $RepoRoot "target\release\tf-cli.exe"

# 3. 各形式で analyze を実行
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-Example([string]$name, [string]$content) {
    $path = Join-Path $exDir $name
    [System.IO.File]::WriteAllText($path, $content, $utf8NoBom)
    Write-Host "  -> $name"
}

Write-Host "generating examples:"

$jsonl = & $exe analyze $lnkPath --format jsonl
Write-Example "analyze_jsonl.jsonl" $jsonl

$json = & $exe analyze $lnkPath --format json
Write-Example "analyze_json.json" $json

$text = & $exe analyze $lnkPath --format text
Write-Example "analyze_text.txt" $text

# CSV・Timesketch は --output で別 directory へ
$csvOut = Join-Path $tmpDir "out.csv"
& $exe analyze $lnkPath --format csv --output $csvOut | Out-Null
Copy-Item $csvOut (Join-Path $exDir "analyze_csv.csv") -Force
Write-Host "  -> analyze_csv.csv"

$tsOut = Join-Path $tmpDir "ts.jsonl"
& $exe analyze $lnkPath --format timesketch --output $tsOut | Out-Null
Copy-Item $tsOut (Join-Path $exDir "analyze_timesketch.jsonl") -Force
Write-Host "  -> analyze_timesketch.jsonl"

$ver = & $exe version
Write-Example "version.txt" $ver

$insp = & $exe inspect $lnkPath
Write-Example "inspect.txt" $insp

Write-Host "=== 完成 ==="
Get-ChildItem $exDir -File | Format-Table Name, Length
