$ErrorActionPreference = 'Stop'
$desktopRoot = $PSScriptRoot
$jdkRoot = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { [IO.Path]::GetFullPath((Join-Path $desktopRoot '..\..\.tools\jdk')) }
& (Join-Path $desktopRoot 'build.ps1')
& (Join-Path $desktopRoot 'extensions\build.ps1')
Push-Location (Join-Path $desktopRoot '..')
try {
    & (Join-Path $jdkRoot 'bin\java.exe') --add-modules jdk.httpserver "-Djava.io.tmpdir=$desktopRoot\build" -jar (Join-Path $desktopRoot 'dist-vuln\vuln.jar') --self-test 2>&1 | Tee-Object -FilePath (Join-Path $desktopRoot 'build\vuln-test-results.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Desktop integration tests failed' }
} finally { Pop-Location }
