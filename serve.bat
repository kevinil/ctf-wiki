@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo [1/2] 构建站点...
call npm run build
if errorlevel 1 (
  echo 构建失败，按任意键退出。
  pause >nul
  exit /b 1
)

echo [2/2] 启动本地预览: http://localhost:4173
start "" http://localhost:4173
call npm run preview
