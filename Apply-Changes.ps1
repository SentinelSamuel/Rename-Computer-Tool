Set-ExecutionPolicy -ExecutionPolicy Bypass -Force -Confirm:$false

$rendomPath = "$env:SystemRoot\System32\rendom.exe"

Start-Process "$rendomPath" -ArgumentList " /clean"
Start-Process "$rendomPath" -ArgumentList " /end"
Start-Process "$env:SystemRoot\System32\dsa.msc"

