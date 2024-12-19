# release_cleaver.ps1

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

# release_cleaver.sh
# Split and join large files into 2 gigabyte chunks. sha256 sum is
#   also calculated and saved on split and checked on join.


$ErrorActionPreference = "Stop"


# Split a binary file into a series of smaller files
#  - FilePath - path to file to be split
#  - OutDir - directory containing resultant fragment files
#  - ChunkSize - maximum size of each file part
#  - BufferSize - intermediate in-memory buffer size
function Split-BinaryFile {
    param (
        [string]$FilePath,
        [string]$OutDir,
        [int64]$ChunkSize = 2000000000,
        [int64]$BufferSize = 1000000
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

# Split a binary file into a series of smaller files
#  - FilePaths - array of files to join (in the order to be reassembled)
#  - OutputFile - Filename of resulting joined file
function Concatenate-BinaryFiles {
    param (
        [string[]]$FilePaths,
        [string]$OutputFile
    )

    $outputFileStream = [System.IO.File]::Create($OutputFile)
    try {
        foreach ($filePath in $FilePaths) {
            $inputFileStream = [System.IO.File]::OpenRead($filePath)
            try {
                $inputFileStream.CopyTo($outputFileStream)
            } finally {
                $inputFileStream.Close()
            }
        }
    }
    finally {
        $outputFileStream.Close()
    }
}

# first expand wildcard arguments ($args -> $allFileArgs)
$allFileArgs = @()
foreach ($filename in $args) {
    $expandedFiles = Get-ChildItem -Path $filename
    foreach ($expandedFile in $expandedFiles) {
        If (-not ($allFileArgs -contains $expandedFile)) {
            $allFileArgs += $expandedFile.FullName
        }
    }
}

if ($allFileArgs.Count -eq 0) {
    Write-Host "Usage:"
    Write-Host "  $(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf) <file_to_split>"
    Write-Host "OR"
    Write-Host "  $(Split-Path -Path $MyInvocation.MyCommand.Path -Leaf) <file_to_join.00> <file_to_join.01> ... <file_to_join.sha>"
    exit 1

} elseif ($allFileArgs.Count -gt 1) {
    Write-Host "Joining..."

    # separate the sha file from the files to join
    $shaFiles = @()
    $splitFiles = @()
    foreach ($filename in $allFileArgs) {
        if (Test-Path $filename -PathType Leaf) {
            if ($filename -like "*.sha") {
                $shaFiles += $filename
            } else {
                $splitFiles += $filename
            }
        } else {
            Write-Host """$($filename)"" does not exist"
            exit 1
        }
    }

    # make sure the base names of the files to join match
    $prevBase = ""
    foreach ($filename in $splitFiles) {
        $curBase = [System.IO.Path]::GetFileNameWithoutExtension($filename);
        if ($prevBase -and ($prevBase -ne $curBase)) {
            Write-Host "File basenames ""$($prevBase)"" and ""$($curBase)"" do not match, giving up"
            exit 1
        } else {
            $prevBase = $curBase
        }
    }
    $outFileBase = $prevBase
    $outFile = Join-Path -Path (Get-Location) -ChildPath (Split-Path -Path $outFileBase -Leaf)

    # don't overwrite an existing file
    if (Test-Path $outFile -PathType Leaf) {
        Write-Host "Output file ""$($outFileBase)"" already exists"
        exit 1
    }

    # join the files
    Concatenate-BinaryFiles $splitFiles $outFile

    # check the results and sha sum
    if (Test-Path $outFile -PathType Leaf) {
        $outFileItem = Get-Item $outFile
        if ($outFileItem.Length -gt 0) {
            if ($shaFiles.Count -ne 1) {
                Write-Host "Files joined to ""$($outFileBase)"", but could not verify file integrity"
                exit 1

            } else {
                # calculate the sha256 sum
                $outFileHash = Get-FileHash -Path $outFile -Algorithm SHA256
                $outFileHashSha256 = $outFileHash.Hash.ToLower()

                # Read the contents of the sha file for comparison
                $shaFileContent = Get-Content $shaFiles[0]
                $shaFileContents = @()
                foreach ($line in $shaFileContent) {
                    $parts = $line -split '\s+'
                    if ($parts.Length -eq 2) {
                        $shaFileContents += @($parts[0].ToLower(), $parts[1])
                        break
                    }
                }

                # compare the joined file and hash from the sha file
                if ($shaFileContents[0] -eq $outFileHashSha256.ToLower()) {
                    Write-Host """$($outFileBase)"" OK"

                } else {
                    Write-Host """$($outFileBase)"" SHA256 hash mismatch ($($shaFileContents[0]) vs $($outFileHashSha256))"
                    exit 1
                }
            }

        } else {
            Write-Host "Attempted to join files to ""$($outFileBase)"", but an empty file resulted"
            exit 1
        }

    } else {
        Write-Host "Attempted to join files to ""$($outFileBase)"", but could not create the file"
        exit 1
    }

} else {
    Write-Host "Splitting..."
    $fileToSplit = $allFileArgs[0]

    # generate sha256 sum file
    $shaFile = Join-Path -Path (Get-Location) -ChildPath ((Split-Path -Path $fileToSplit -Leaf) + ".sha")
    (Get-FileHash -Algorithm SHA256 -Path $fileToSplit | Select-Object -ExpandProperty Hash).ToLower() | Select-Object -First 64 | Out-File -FilePath $shaFile -NoNewline
    Add-Content -Path $shaFile -NoNewline -Value '  '
    Add-Content -Path $shaFile -Value (Split-Path -Path $fileToSplit -Leaf)

    # split the file into its parts
    Split-BinaryFile $fileToSplit (Get-Location)

    Get-Content $shaFile | Write-Host
}