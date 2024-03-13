# release_cleaver.ps1

# Copyright (c) 2024 Battelle Energy Alliance, LLC.  All rights reserved.

# Split and join large files into 2 gigabyte chunks. sha256 sum is
# also calculated and saved on split and checked on join.

if (-not $PSVersionTable.PSVersion) {
    Write-Host "Wrong interpreter, please run \"$($MyInvocation.MyCommand.Path)\" with PowerShell"
    exit 1
}

if (-not (Get-Command -Name "Split-Path" -ErrorAction SilentlyContinue) -or
    -not (Get-Command -Name "Get-FileHash" -ErrorAction SilentlyContinue) -or
    -not (Get-Command -Name "Join-Path" -ErrorAction SilentlyContinue) -or
    -not (Get-Command -Name "cat" -ErrorAction SilentlyContinue)) {
    Write-Error "$($MyInvocation.MyCommand.Path) requires Split-Path, Get-FileHash, Join-Path and cat"
    exit 1
}

$ErrorActionPreference = "Stop"

function Get-BaseName {
    param([string]$path)
    return (Split-Path -Path $path -Leaf).Split(".")[0]
}

function Get-Extension {
    param([string]$path)
    return (Split-Path -Path $path -Leaf).Split(".")[-1]
}

function Split-BinaryFile {
    param (
        [string]$FilePath,
        [string]$OutDir,
        [int64]$ChunkSize = 2000000000,
        [int64]$BufferSize = 1MB
    )

    $fileStream = [System.IO.File]::OpenRead($FilePath)

    try {
        $chunkIndex = 1
        $bytesReadTotal = 0

        while ($bytesReadTotal -lt $fileStream.Length) {
            $chunkFilePath = "{0}.{1:D2}" -f (Join-Path -Path $OutDir -ChildPath (Split-Path -Path $FilePath -Leaf)), $chunkIndex
            $chunkIndex++

            $chunkFileStream = [System.IO.File]::Create($chunkFilePath)
            try {
                $bytesRead = 0
                $buffer = New-Object byte[] $BufferSize

                while ($bytesRead -lt $ChunkSize -and ($bytesReadTotal + $bytesRead) -lt $fileStream.Length) {
                    $bytesToRead = [math]::Min($ChunkSize - $bytesRead, $BufferSize)
                    $read = $fileStream.Read($buffer, 0, $bytesToRead)
                    $chunkFileStream.Write($buffer, 0, $read)
                    $bytesRead += $read
                }

                $bytesReadTotal += $bytesRead
            } finally {
                $chunkFileStream.Close()
            }
        }
    } finally {
        $fileStream.Close()
    }
}


if ($args.Count -eq 0) {
    Write-Host "Usage:"
    Write-Host "  $(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf) <file_to_split>"
    Write-Host "OR"
    Write-Host "  $(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf) <file_to_join.00> <file_to_join.01> ... <file_to_join.sha>"
    exit 1

} elseif ($args.Count -gt 1) {

} else {
    Write-Host "Splitting..."
    $fileToSplit = $args[0]

    # generate sha256 sum file
    $shaFile = Join-Path -Path (Get-Location) -ChildPath ((Split-Path -Path $fileToSplit -Leaf) + ".sha")
    (Get-FileHash -Algorithm SHA256 -Path $fileToSplit | Select-Object -ExpandProperty Hash).ToLower() | Select-Object -First 64 | Out-File -FilePath $shaFile -NoNewline
    Add-Content -Path $shaFile -NoNewline -Value '  '
    Add-Content -Path $shaFile -Value (Split-Path -Path $fileToSplit -Leaf)

    Split-BinaryFile $fileToSplit (Get-Location)
}