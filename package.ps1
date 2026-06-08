param(
    [string]$Output = "..\hideSceneport_module.zip"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Loader = Join-Path $Root "system\bin\hideport_loader"
if ([System.IO.Path]::IsPathRooted($Output)) {
    $OutputPath = $Output
} else {
    $OutputPath = Join-Path $Root $Output
}

if (-not (Test-Path -LiteralPath $Loader)) {
    throw "Missing executable: $Loader. Build it first."
}

if (Test-Path -LiteralPath $OutputPath) {
    Remove-Item -LiteralPath $OutputPath -Force
}

$Fingerprint = Join-Path $Root "kernel_btf.sha256"
$BtfCandidates = @(
    (Join-Path $Root "btf\vmlinux.btf"),
    (Join-Path $Root "vmlinux.btf")
)
$BtfSource = $BtfCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

if ($BtfSource) {
    (Get-FileHash -Algorithm SHA256 -LiteralPath $BtfSource).Hash.ToLowerInvariant() |
        Set-Content -LiteralPath $Fingerprint -NoNewline -Encoding ascii
    Write-Host "Wrote kernel BTF fingerprint from $BtfSource"
} elseif (Test-Path -LiteralPath $Fingerprint) {
    Remove-Item -LiteralPath $Fingerprint -Force
    Write-Host "Removed stale kernel BTF fingerprint"
} else {
    Write-Warning "No vmlinux.btf found; package will not enforce kernel BTF match."
}

$items = @(
    "module.prop",
    "hideport.conf",
    "post-fs-data.sh",
    "service.sh",
    "hideport_start.sh",
    "customize.sh",
    "uninstall.sh"
)

if (Test-Path -LiteralPath $Fingerprint) {
    $items += "kernel_btf.sha256"
}

$Stage = Join-Path ([System.IO.Path]::GetTempPath()) ("hideSceneport-package-" + [Guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory -Path (Join-Path $Stage "system\bin") -Force | Out-Null

    foreach ($item in $items) {
        Copy-Item -LiteralPath (Join-Path $Root $item) -Destination (Join-Path $Stage $item) -Force
    }
    Copy-Item -LiteralPath $Loader -Destination (Join-Path $Stage "system\bin\hideport_loader") -Force

    $archiveItems = Get-ChildItem -LiteralPath $Stage -Force
    Compress-Archive -LiteralPath $archiveItems.FullName -DestinationPath $OutputPath -Force
} finally {
    if (Test-Path -LiteralPath $Stage) {
        Remove-Item -LiteralPath $Stage -Recurse -Force
    }
}
Write-Host "Wrote $OutputPath"
