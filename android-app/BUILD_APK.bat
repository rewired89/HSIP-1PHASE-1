@echo off
echo ============================================
echo HSIP Keyboard APK Builder
echo ============================================
echo.

cd /d "%~dp0"

echo Cleaning previous builds...
if exist "app\build\outputs\apk" rmdir /s /q "app\build\outputs\apk"

echo.
echo Building APK...
echo.

call gradlew.bat clean assembleDebug

echo.
echo ============================================
if exist "app\build\outputs\apk\debug\app-debug.apk" (
    echo SUCCESS! APK created at:
    echo %cd%\app\build\outputs\apk\debug\app-debug.apk
    echo.
    echo Opening folder...
    start "" explorer "%cd%\app\build\outputs\apk\debug"
) else (
    echo FAILED! APK was not created.
    echo Check the error messages above.
)
echo ============================================
echo.
pause
