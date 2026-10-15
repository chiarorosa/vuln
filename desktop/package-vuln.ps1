$ErrorActionPreference='Stop'
$desktopRoot=$PSScriptRoot
$jdkRoot = if ($env:JAVA_HOME) { $env:JAVA_HOME } else { [IO.Path]::GetFullPath((Join-Path $desktopRoot '..\..\.tools\jdk')) }
& (Join-Path $desktopRoot 'build.ps1')
& (Join-Path $desktopRoot 'extensions\build.ps1')
$toolsDir=Join-Path $desktopRoot 'build\icon-tools'
New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
$iconClasspath=(Join-Path $desktopRoot 'build\vuln-product-classes')+';'+(Join-Path $desktopRoot 'lib\flatlaf.jar')
& (Join-Path $jdkRoot 'bin\javac.exe') --release 21 -cp $iconClasspath -d $toolsDir (Join-Path $desktopRoot 'tools\GenerateIcon.java')
if($LASTEXITCODE -ne 0){throw 'Icon tool compilation failed'}
& (Join-Path $jdkRoot 'bin\java.exe') -cp ($toolsDir+';'+$iconClasspath) GenerateIcon (Join-Path $desktopRoot 'assets')
if($LASTEXITCODE -ne 0){throw 'Icon generation failed'}
$runtime=Join-Path $desktopRoot 'build\runtime-vuln'
if(-not(Test-Path -LiteralPath $runtime)){
    & (Join-Path $jdkRoot 'bin\jlink.exe') --add-modules java.desktop,java.net.http,jdk.httpserver,jdk.crypto.ec,java.logging,java.management --strip-debug --no-header-files --no-man-pages --output $runtime
    if($LASTEXITCODE -ne 0){throw 'VULN runtime packaging failed'}
}
$destination=Join-Path $desktopRoot 'releases\3.2.1'
$image=Join-Path $destination 'VULN'
if(Test-Path -LiteralPath (Join-Path $image 'VULN.exe')){
    Copy-Item -LiteralPath (Join-Path $desktopRoot 'dist-vuln\vuln.jar') -Destination (Join-Path $image 'app\vuln.jar') -Force
    Copy-Item -LiteralPath (Join-Path $desktopRoot 'dist-vuln\lib\flatlaf.jar') -Destination (Join-Path $image 'app\lib\flatlaf.jar') -Force
}else{
    & (Join-Path $jdkRoot 'bin\jpackage.exe') --type app-image --name VULN --app-version 3.2.1 --vendor VULN --description 'Network Security Workspace' --input (Join-Path $desktopRoot 'dist-vuln') --main-jar vuln.jar --main-class VulnApp --runtime-image $runtime --dest $destination --icon (Join-Path $desktopRoot 'assets\vuln.ico') --java-options '--add-modules=jdk.httpserver'
    if($LASTEXITCODE -ne 0){throw 'VULN executable packaging failed'}
}
$extensionDir=Join-Path $image 'extensions'
New-Item -ItemType Directory -Path $extensionDir -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $desktopRoot 'extensions\dist\header-inspector.jar') -Destination $extensionDir -Force
Copy-Item -LiteralPath (Join-Path $desktopRoot 'lib\FlatLaf-LICENSE.txt') -Destination $image -Force
Copy-Item -LiteralPath (Join-Path $desktopRoot 'README-3.2.1.md') -Destination (Join-Path $image 'README.md') -Force
Copy-Item -LiteralPath (Join-Path $desktopRoot 'VULN-Roadmap.md') -Destination $image -Force
& (Join-Path $jdkRoot 'bin\java.exe') -cp (Join-Path $desktopRoot 'build\vuln-product-classes') WikiContent (Join-Path $image 'VULN-Wiki-pt-BR.md')
if($LASTEXITCODE -ne 0){throw 'Wiki export failed'}
$verifyScript=Join-Path $desktopRoot 'verify-product.ps1'
if(Test-Path -LiteralPath $verifyScript){& $verifyScript -ImagePath $image}
Write-Output (Join-Path $image 'VULN.exe')
