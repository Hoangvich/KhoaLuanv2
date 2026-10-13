# Mở 3 cửa sổ: API (cổng 8000), pipeline, frontend (cổng 5173). Chạy từ thư mục gốc project:
#   powershell -ExecutionPolicy Bypass -File scripts\start.ps1
$root = Split-Path $PSScriptRoot -Parent
$be = "$root\backend"
$py = "$be\.venv\Scripts\python.exe"
Start-Process powershell -ArgumentList '-NoExit', '-Command', "`$env:PYTHONUTF8='1'; Set-Location '$be'; `$host.UI.RawUI.WindowTitle='IDS API'; & '$py' -m uvicorn app.main:app --port 8000"
Start-Process powershell -ArgumentList '-NoExit', '-Command', "`$env:PYTHONUTF8='1'; Set-Location '$be'; `$host.UI.RawUI.WindowTitle='IDS Pipeline'; & '$py' -m pipeline.run"
Start-Process powershell -ArgumentList '-NoExit', '-Command', "Set-Location '$root\frontend'; `$host.UI.RawUI.WindowTitle='IDS Frontend'; npm run dev"
Start-Sleep -Seconds 6
Start-Process 'http://localhost:5173'
Write-Host 'Dashboard: http://localhost:5173  (admin / admin123)   API docs: http://localhost:8000/docs'
