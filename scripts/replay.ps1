# Phát lại pcap như sensor CICFlowMeter (khi chưa có cổng SPAN). Ví dụ:
#   powershell -ExecutionPolicy Bypass -File scripts\replay.ps1 portscan.pcap ddos.pcap
#   powershell -ExecutionPolicy Bypass -File scripts\replay.ps1 bruteforce.pcap --speed 20
$root = Split-Path $PSScriptRoot -Parent
$env:PYTHONUTF8 = '1'
Set-Location "$root\backend"
& "$root\backend\.venv\Scripts\python.exe" -m tools.replay_pcap @args
