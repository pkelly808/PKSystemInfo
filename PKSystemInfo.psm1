function Get-PKIPInfo {

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string[]]$ComputerName
)

    PROCESS {

        Write-Verbose "Processing Get-PKIPInfo..."

        foreach ($Computer in $ComputerName.ToUpper()) {

            try {
                Write-Verbose "Get-WmiObject for $Computer"
                $Networks = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE -ComputerName $Computer -ea Stop
            } catch {
                Write-Warning "$Computer; $($_.Exception.Message); Line $($_.InvocationInfo.ScriptLineNumber)"
                continue
            }

            foreach ($Network in $Networks) {
                $props = [ordered]@{
                    'ComputerName'=$Computer;
                    'Adapter'=$Network.Description;
                    'Index'=$Network.Index;
                    'IPAddress'=$Network | select -ExpandProperty IPAddress;
                    'SubnetMask'=$Network | select -ExpandProperty IPSubnet;
                    'Gateway'=$Network | select -ExpandProperty DefaultIPGateway;
                    'DNS'=$Network | select -ExpandProperty DNSServerSearchOrder;
                }

                $obj = New-Object -TypeName PSObject -Property $props
                Write-Output $obj
            }
        }
    }
}

function Get-PKDriveInfo {

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string[]]$ComputerName
)

    PROCESS {

        Write-Verbose "Processing Get-PKDriveInfo..."

        foreach ($Computer in $ComputerName.ToUpper()) {

            try {
                Write-Verbose "Get-WmiObject for $Computer"
                $Disks = Get-WmiObject -Class Win32_LogicalDisk -Filter 'DriveType=3' -ComputerName $Computer -ea Stop
            } catch {
                Write-Warning "$Computer; $($_.Exception.Message); Line $($_.InvocationInfo.ScriptLineNumber)"
                continue
            }

            foreach ($Disk in $Disks) {
                $props = [ordered]@{
                    'ComputerName'=$Computer;
                    'DeviceId'=$Disk.DeviceId;
                    'Size'=$Disk.Size;
                    'FreeSpace'=$Disk.FreeSpace;
                }

                $obj = New-Object -TypeName PSObject -Property $props
                $obj.PSObject.TypeNames.Insert(0,�PKSystemInfo.DriveInfo�)
                Write-Output $obj
            }

        }
    }
}

function Get-PKSystemInfo {
<#
.SYNOPSIS
Queries System Information from computers using WMI.  Powershell is used as well if Remote Management is enabled.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string[]]$ComputerName
)

    PROCESS {

        Write-Verbose "Processing Get-PKIPInfo..."

        foreach ($Computer in $ComputerName.ToUpper()) {

            try {
                Write-Verbose "Get-WmiObject for $Computer"
                $OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ea Stop
                $CS = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Computer -ea Stop
                $Bios = Get-WmiObject -Class Win32_Bios -ComputerName $Computer -ea Stop
                $Proc = Get-WmiObject -Class Win32_Processor -ComputerName $Computer -ea Stop
                $Drives = Get-WmiObject -Class Win32_LogicalDisk -Filter 'DriveType=3' -ComputerName $Computer -ea Stop
            } catch {
                Write-Warning "$Computer; $($_.Exception.Message); Line $($_.InvocationInfo.ScriptLineNumber)"
                continue
            }

            #Count is empty if only 1 object returned
            if ($Proc.Count) {
                $CpuSockets = $Proc.Count
                $CpuCores = $Proc[0].NumberOfCores
                $CpuSpeed = $Proc[0].MaxClockSpeed/1000
            } else {
                $CpuSockets = 1
                $CpuCores = $Proc.NumberOfCores
                $CpuSpeed = $Proc.MaxClockSpeed/1000
            }

            #Count is empty if only 1 object returned
            if ($Drives.Count) {
                $DriveCount = $Drives.Count
            } else {
                $DriveCount = 1
            }

            #Test and Use WinRM for PowerShell Version (requires auntentication)
            if (Test-WSMan $Computer -ea SilentlyContinue) {
                $WSMan = $true
                $PS = Invoke-Command $Computer {$PSVersionTable.PSVersion.Major} -ea SilentlyContinue
            } else {
                $WSMan = $false
                $PS = $null
            }
            
            $props = [ordered]@{
                'ComputerName'=$Computer;
                'Manufacturer'=$CS.Manufacturer;
                'Model'=$CS.Model;
                'Virtual'=if ($CS.Model -like "*Virtual*" -or $CS.Model -eq 'KVM') {$true} else {$false};
                'Serial'=$Bios.SerialNumber;
                'OperatingSystem'=$OS.Caption;                        
                'ServicePack'=$OS.ServicePackMajorVersion;
                'LastBoot'=[Management.ManagementDateTimeConverter]::ToDateTime($OS.LastBootUptime);
                'CpuSockets'=$CpuSockets;
                'CpuCores'=$CpuCores;
                'CpuGHz'=$CpuSpeed;
                'HD'=$DriveCount;
                'RAM'=$CS.TotalPhysicalMemory;
                'IPAddress'=[System.Net.Dns]::GetHostByName($Computer).AddressList | foreach {$_.IPAddressToString}
                'RemoteManagement'=$WSMan;
                'PowerShell'=$PS;
            }

            $obj = New-Object -TypeName PSObject -Property $props
            $obj.PSObject.TypeNames.Insert(0,�PKSystemInfo.SystemInfo�)
            Write-Output $obj
        }
    }
}
