# Download Gradle Wrapper JAR
$wrapperDir = "gradle\wrapper"
$wrapperJar = "$wrapperDir\gradle-wrapper.jar"

if (!(Test-Path $wrapperDir)) {
    New-Item -ItemType Directory -Force -Path $wrapperDir
}

Write-Host "Downloading Gradle wrapper JAR..."
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/gradle/gradle/master/gradle/wrapper/gradle-wrapper.jar" -OutFile $wrapperJar

Write-Host "Wrapper JAR downloaded to: $wrapperJar"
Write-Host "Now run: .\gradlew.bat assembleDebug"
