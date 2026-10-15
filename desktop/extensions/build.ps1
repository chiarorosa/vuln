$ErrorActionPreference = 'Stop'
$extensionRoot = $PSScriptRoot
$jdkRoot = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { [IO.Path]::GetFullPath((Join-Path $extensionRoot '..\..\..\.tools\jdk')) }
$classes = Join-Path $extensionRoot 'build-vuln'
$dist = Join-Path $extensionRoot 'dist'
New-Item -ItemType Directory -Path $classes,$dist -Force | Out-Null
& (Join-Path $jdkRoot 'bin\javac.exe') --release 21 -encoding UTF-8 -cp (Join-Path $extensionRoot '..\dist-vuln\vuln.jar') -d $classes (Join-Path $extensionRoot 'src\HeaderInspector.java')
if ($LASTEXITCODE -ne 0) { throw 'Extension compilation failed' }
& (Join-Path $jdkRoot 'bin\jar.exe') --create --file (Join-Path $dist 'header-inspector.jar') -C $classes . -C (Join-Path $extensionRoot 'resources') .
if ($LASTEXITCODE -ne 0) { throw 'Extension packaging failed' }
Write-Output (Join-Path $dist 'header-inspector.jar')
