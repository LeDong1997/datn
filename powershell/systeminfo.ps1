$Computer = (Get-WmiObject -Class Win32_ComputerSystem -Property Name).Name

$Connection = Test-Connection $Computer -Count 1 -Quiet

if ($Connection -eq "True"){

   $ComputerHW = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Computer | Select-Object -Property Model,Manufacturer | % {"$($_.Model)||$($_.Manufacturer)|||"} 

   $ComputerCPU = Get-WmiObject -Class Win32_Processor -ComputerName $Computer | Select-Object -Property Name | % {"$($_.Name)|||"}

   $ComputerRAM = Get-WmiObject -Class Win32_PhysicalMemory -ComputerName $Computer | Select-Object -Property Description,Manufacturer,Capacity,Speed | % {"$($_.Description)||$($_.Manufacturer)||$($_.Capacity/1GB)||$($_.Speed)|||"} 
   
   $ComputerVideoCard = Get-WmiObject -Class Win32_VideoController -ComputerName $Computer | Select-Object -Property Name, MaxRefreshRate,VideoModeDescription | % {"$($_.Name)||$($_.MaxRefreshRate)||$($_.VideoModeDescription)|||"} 
   
   $ComputerAudio = Get-WmiObject -Class Win32_SoundDevice -ComputerName $Computer | Select-Object -Property Name | % {"$($_.Name)|||"} 

   $ComputerDisks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $Computer | Select-Object -Property DeviceID,Size,FreeSpace | % {"$($_.DeviceID)||$($_.Size/1GB)||$($_.FreeSpace/1GB)|||"} 
   
   $ComputerTime = Get-WmiObject -Class Win32_LocalTime -ComputerName $Computer | Select-Object -Property Hour,Minute,Second,Day,Month,Year | % {"$($_.Hour)||$($_.Minute)||$($_.Second)||$($_.Day)||$($_.Month)||$($_.Year)|||"} 
   
   $ComputerNetwork = Get-WmiObject -Class Win32_NetworkAdapter -ComputerName $Computer | Select-Object -Property Name,AdapterType,MACAddress | % {"$($_.Name)||$($_.AdapterType)||$($_.MACAddress)|||"}
   
   $ComputerOS = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer).Version

   switch -Wildcard ($ComputerOS){
      "6.1.7600" {$OS = "Windows 7"; break}
      "6.1.7601" {$OS = "Windows 7 SP1"; break}
      "6.2.9200" {$OS = "Windows 8"; break}
      "6.3.9600" {$OS = "Windows 8.1"; break}
      "10.0.*" {$OS = "Windows 10"; break}
      default {$OS = "Unknown Operativng System"; break}
   }

   Write-Host "$OS|||"
   Write-Host "*****"
   Write-Host "Model||Manufacturer|||"
   Write-Output $ComputerHW
   Write-Host "*****"
   Write-Host "Processor|||"
   Write-Output $ComputerCPU
   Write-Host "*****"
   Write-Host "Memory||Manufacturer||Capacity||Speed|||"
   Write-Output $ComputerRAM
   Write-Host "*****"
   Write-Host "VGA||Refresh Rate||Resolution|||"
   Write-Output $ComputerVideoCard
   Write-Host "*****"
   Write-Host "Sound Device|||"
   Write-Output $ComputerAudio
   Write-Host "*****"
   Write-Host "Disk Name||Total Size||Free Space|||"
   Write-Output $ComputerDisks
   Write-Host "*****"
   Write-Host "Network Adpater||Type||MAC Address|||"
   Write-Output $ComputerNetwork
   }
else {
   Write-Host -ForegroundColor Red @"

Computer is not reachable or does not exists.

"@
}
