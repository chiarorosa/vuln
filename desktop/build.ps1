$ErrorActionPreference = 'Stop'
$desktopRoot = $PSScriptRoot
$jdkRoot = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { [IO.Path]::GetFullPath((Join-Path $desktopRoot '..\..\.tools\jdk')) }
$classDir = Join-Path $desktopRoot 'build\vuln-product-classes'
$distDir = Join-Path $desktopRoot 'dist-vuln'
$libDir = Join-Path $distDir 'lib'
New-Item -ItemType Directory -Path $classDir,$distDir,$libDir -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $desktopRoot 'lib\flatlaf.jar') -Destination $libDir -Force
Copy-Item -LiteralPath (Join-Path $desktopRoot 'lib\FlatLaf-LICENSE.txt') -Destination $libDir -Force
Copy-Item -LiteralPath (Join-Path $desktopRoot 'lib\rhino.jar') -Destination $libDir -Force
$javaSources = @(Get-ChildItem -LiteralPath (Join-Path $desktopRoot 'src') -Filter '*.java' | ForEach-Object FullName)
& (Join-Path $jdkRoot 'bin\javac.exe') --release 21 --add-modules jdk.httpserver -encoding UTF-8 -cp ((Join-Path $desktopRoot 'lib\flatlaf.jar')+';'+(Join-Path $desktopRoot 'lib\rhino.jar')) -d $classDir @javaSources
if ($LASTEXITCODE -ne 0) { throw 'Java compilation failed' }
$manifestPath=Join-Path $desktopRoot 'build\vuln-manifest.mf'
[IO.File]::WriteAllText($manifestPath,"Manifest-Version: 1.0`nMain-Class: VulnApp`nClass-Path: lib/flatlaf.jar lib/rhino.jar`n`n",[Text.UTF8Encoding]::new($false))
& (Join-Path $jdkRoot 'bin\jar.exe') --create --file (Join-Path $distDir 'vuln.jar') --manifest $manifestPath -C $classDir .
if ($LASTEXITCODE -ne 0) { throw 'JAR packaging failed' }
Write-Output (Join-Path $distDir 'vuln.jar')
