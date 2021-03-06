$RAM= Get-WMIObject Win32_PhysicalMemory | Measure -Property capacity -Sum | %{$_.sum/1Mb}
$CpuCores = (Get-WMIObject Win32_ComputerSystem).NumberOfLogicalProcessors
$properties=@(
    @{Name="Process Name"; Expression = {$_.name}},
    @{Name="1"; Expression = {"||"}},
    @{Name="CPU (%)"; Expression = {[Decimal]::Round(($_.CookedValue / $CpuCores), 2)}}, 
    @{Name="3"; Expression = {"||"}}   
    @{Name="Memory (%)"; Expression = {[Math]::Round(($_.workingSetPrivate / 1mb)/$RAM*100,2)}},
    @{Name="4"; Expression = {"||"}}
    @{Name="Elapsed Time (m)"; Expression = {$_.ElapsedTime}},
    @{Name="2"; Expression = {"||"}},
    @{Name="Pid"; Expression = {$_.IDProcess}},
    @{Name="end"; Expression = {"|||"}}
)
Get-WmiObject -class Win32_PerfFormattedData_PerfProc_Process | 
    Select-Object $properties | Sort-Object -Property  @{Expression = "Memory (%)"; Descending = $True}  | Select-Object -First 20 | Format-Table -AutoSize

