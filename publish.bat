@echo off
echo Building qsafe-sign...

call npm run build:min
if errorlevel 1 (
    echo Build failed. Aborting.
    pause
    exit /b 1
)
echo.

set /p PUBLISH="Publish to npm? (y/n): "
if /i not "%PUBLISH%"=="y" (
    echo Build complete. Nothing published.
    pause
    exit /b 0
)

call npm version patch
call npm publish --access public
echo Done.
pause