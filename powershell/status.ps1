$os = Get-WmiObject win32_operatingsystem
function Get-Uptime {
   $uptime = (Get-Date) - ($os.ConvertToDateTime($os.lastbootuptime))
   $Display = "Uptime : " + $Uptime.Hours + " hours, " + $Uptime.Minutes + " minutes, " + $Uptime.Seconds + " seconds|||" 
   Write-Output $Display
}

function Get-CPUUsage{
   $CPU = Get-WmiObject win32_processor | Measure-Object -property LoadPercentage -Average | Select Average 
   $Display = "CPU Usage : " + $CPU.Average + "%|||"
   Write-Output $Display
}

function Get-MemoryUsage{
   $RAM = [math]::Round(($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/1KB)
   $TotalRAM = [math]::Round(($os.TotalVisibleMemorySize/1KB),2)
   $RAMpct=[math]::Round(($RAM/$TotalRAM)*100,2)
   $Display = "RAM Usage : " + $RAM +  "||" + $TotalRAM + "||" + $RAMpct + "|||"
   Write-Output $Display
}

function Get-SwapUsage{
   $Swap = Get-WmiObject Win32_PageFileusage | Select-Object CurrentUsage,AllocatedBaseSize
   $Swappct=[math]::Round(($Swap.CurrentUsage/$Swap.AllocatedBaseSize)*100,2)
   $Display = "Swap Usage : " + $Swap.CurrentUsage + "||" + $Swap.AllocatedBaseSize + "||"+ $Swappct + "%|||"
   Write-Output $Display
}

function Get-NumberofProcesses{
   $TotalProcess = (Get-Service).Count
   $RunningProcess = (Get-Service | Where-Object {$_.Status -eq 'Running'}).Count
   $Display = "Processes : " + $TotalProcess + " ,Running : " + $RunningProcess
   Write-Output $Display
}

Get-Uptime
Get-CPUUsage
Get-MemoryUsage
Get-SwapUsage
Get-NumberofProcesses