powershell -ExecutionPolicy Bypass -File .\install.ps1
Invoke-Expression $command
$secure = ConvertTo-SecureString "hunter2hunter" -AsPlainText -Force
