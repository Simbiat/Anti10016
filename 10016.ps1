# ================================================================
# From
# https://github.com/Simbiat/Anti10016/blob/main/10016.ps1
# Based on
# https://gist.github.com/kitmenke/3213d58ffd60ae9873ca466f143945f4
# and
# https://gist.github.com/Parahexen/c8a2e8d553eb3ac5d15d0a2e0687f05e
# with some optimisation and replacement of CLASSES_ROOT due to
# https://stackoverflow.com/questions/53984433/hkey-local-machine-software-classes-vs-hkey-classes-root
# Refinement to work on domain controllers by Sean Gallagher and Matthew Prentice
# ================================================================


# To take ownership of a registry key:
# https://social.technet.microsoft.com/Forums/windowsserver/en-US/e718a560-2908-4b91-ad42-d392e7f8f1ad/take-ownership-of-a-registry-key-and-change-permissions?forum=winserverpowershell
# ************************* START enable-privilege
function enable-privilege {
    param(
        ## The privilege to adjust. This set is taken from
        ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
        [ValidateSet(
            'SeAssignPrimaryTokenPrivilege','SeAuditPrivilege','SeBackupPrivilege',
            'SeChangeNotifyPrivilege','SeCreateGlobalPrivilege','SeCreatePagefilePrivilege',
            'SeCreatePermanentPrivilege','SeCreateSymbolicLinkPrivilege','SeCreateTokenPrivilege',
            'SeDebugPrivilege','SeEnableDelegationPrivilege','SeImpersonatePrivilege','SeIncreaseBasePriorityPrivilege',
            'SeIncreaseQuotaPrivilege','SeIncreaseWorkingSetPrivilege','SeLoadDriverPrivilege',
            'SeLockMemoryPrivilege','SeMachineAccountPrivilege','SeManageVolumePrivilege',
            'SeProfileSingleProcessPrivilege','SeRelabelPrivilege','SeRemoteShutdownPrivilege',
            'SeRestorePrivilege','SeSecurityPrivilege','SeShutdownPrivilege','SeSyncAgentPrivilege',
            'SeSystemEnvironmentPrivilege','SeSystemProfilePrivilege','SeSystemtimePrivilege',
            'SeTakeOwnershipPrivilege','SeTcbPrivilege','SeTimeZonePrivilege','SeTrustedCredManAccessPrivilege',
            'SeUndockPrivilege','SeUnsolicitedInputPrivilege')]
        $Privilege,
        ## The process on which to adjust the privilege. Defaults to the current process.
        $ProcessId = $pid,
        ## Switch to disable the privilege, rather than enable it.
        [switch]$Disable
    )

    ## Taken from P/Invoke.NET with minor adjustments.
    $definition = @'
using System;
using System.Runtime.InteropServices;
public class AdjPriv { [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid {
        public int Count;
        public long Luid;
        public int Attr;
    }
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static bool EnablePrivilege(long processHandle, string privilege, bool disable) {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = new IntPtr(processHandle);
        IntPtr htok = IntPtr.Zero;
        retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        if (disable) {
            tp.Attr = SE_PRIVILEGE_DISABLED;
        }
        else {
            tp.Attr = SE_PRIVILEGE_ENABLED;
        }
        retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
        retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return retVal;
    }
}
'@

    $processHandle = (Get-Process -id $ProcessId).Handle
    $type = Add-Type $definition -PassThru
    $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}
# ************************* END enable-privilege



function fixnew([string]$clsid, [string]$appid, [string]$user, [string]$user_alt) {
    #Enable priviliges for the process
    enable-privilege SeTakeOwnershipPrivilege | Out-Null
    enable-privilege SeRestorePrivilege | Out-Null

    #List of users to which we will try to give permissions in DCOM
    $users = [System.Collections.ArrayList]@()
    if (Select-String -Pattern 'S-\d-(?:\d+-){1,14}\d+' -InputObject $user) {
        $users.Add($user) | Out-Null
    }
    if (Select-String -Pattern 'S-\d-(?:\d+-){1,14}\d+' -InputObject $user_alt) {
        $users.Add($user_alt) | Out-Null
    }
    #Add LOCAL SERVICE
    if ($user -ne 'S-1-5-19' -and $user_alt -ne 'S-1-5-19') {
        $users.Add('S-1-5-19') | Out-Null
    }
    #Add SYSTEM
    if ($user -ne 'S-1-5-18' -and $user_alt -ne 'S-1-5-18') {
        $users.Add('S-1-5-18') | Out-Null
    }
    #Add Domain Administrators or Builtin\Administrators as appropriate
    try {
        $users.add($administrators.Translate('System.Security.Principal.SecurityIdentifier').Value) | Out-Null
    } catch {
        if ($user -ne 'S-1-5-32-544' -and $user_alt -ne 'S-1-5-32-544') {
            $users.Add('S-1-5-32-544') | Out-Null
        }
    }

    #Generate array of keys
    $keys = [System.Collections.ArrayList]@()
    $keys.Add([Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("Software\Classes\CLSID\$clsid", 'ReadWriteSubTree', 'TakeOwnership')) | Out-Null
    $keys.Add([Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Classes\CLSID\$clsid", 'ReadWriteSubTree', 'TakeOwnership')) | Out-Null
    $keys.Add([Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("Software\Classes\AppID\$appid", 'ReadWriteSubTree', 'TakeOwnership')) | Out-Null
    $keys.Add([Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Classes\AppID\$appid", 'ReadWriteSubTree', 'TakeOwnership')) | Out-Null

    $item = 1
    foreach ($key in $keys) {
        #Check if registry path was opened
        if ($key) {
            write-host "Processing $key..."
            #Ownership to administrators
            write-host "Taking ownership..."
            $acl = $key.GetAccessControl()
            $acl.SetOwner($administrators)
            $key.SetAccessControl($acl)
            $acl = $key.GetAccessControl()
            $acl.SetAccessRule($fullAccess)
            $key.SetAccessControl($acl)
            #Fix DCOM for AppID
            if ($item -eq 3 -or $item -eq 4) {
                if ($item -eq 3) {
                    $key_update = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("Software\Classes\AppID\$appid", 'ReadWriteSubTree', 'ReadKey, SetValue')
                } else {
                    $key_update = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey("Software\Classes\AppID\$appid", 'ReadWriteSubTree', 'ReadKey, SetValue')
                }
                #Iterrate the users' list
                foreach ($user in $users) {
                    write-host (-join('Fixing ', $key_update.GetValue(''), ' for ', $user, '...'))
                    if (-not($key_update.GetValue('LaunchPermission') -ne $null)) {
                        write-host 'Missing permissions. Creating initial ones...'
                        $sd = (New-Object System.Security.AccessControl.RawSecurityDescriptor ("O:SYG:SYD:(A;;CCDCSW;;;$user)S:")).GetSddlForm('Access')
                        $sid = $sd.Substring($sd.LastIndexOf(';') + 1).TrimEnd(')')
                        #Set ownership to SYSTEM
                        $ace = "O:SYG:SYD:(A;;CCDCSW;;;$sid)"
                        $value = ([wmiclass]'Win32_SecurityDescriptorHelper').SDDLToBinarySD($ace).BinarySD
                        $key_update.SetValue('LaunchPermission', $value, 3)
                        Write-Host 'Permissions updated' -ForegroundColor Green
                    } else {
                        $permissions = $key_update.GetValue('LaunchPermission')
                        $sddl = ([wmiclass]'Win32_SecurityDescriptorHelper').BinarySDToSDDL($permissions).SDDL 
                        if ($sddl) {
                            $changes = "SDDL:`t$sddl`n"
                            #write-host $changes
                            $sd = (New-Object System.Security.AccessControl.RawSecurityDescriptor ("O:SYG:SYD:(A;;CCDCSW;;;$user)S:")).GetSddlForm('Access')
                            $sid = $sd.Substring($sd.LastIndexOf(';') + 1).TrimEnd(')')
                            $ace = "(A;;CCDCSW;;;$sid)"
                            $changes = -join($changes, "ACE:`t$ace`n")
                            if ($sddl.IndexOf($ace) -eq -1) {
                                if ($sddl.LastIndexOf('S:') -eq -1) {
                                    $sddl += $ace
                                } else {
                                    $sddl = $sddl.Insert($sddl.LastIndexOf('S:'),$ace)
                                }
                                $changes = -join($changes, "New:`t$sddl")
                                $value = ([wmiclass]'Win32_SecurityDescriptorHelper').SDDLToBinarySD($sddl).BinarySD
                                if ($value) {
                                    $key_update.SetValue('LaunchPermission', $value)
                                    Write-Host $changes
                                    Write-Host 'Permissions updated' -ForegroundColor Green
                                } else {
                                    Write-Host 'Failed to set new SDDL' -ForegroundColor Red
                                }
                            } else {
                                Write-Host 'Already fixed, skipping...' -ForegroundColor Green
                            }
                        } else {
                            Write-Host 'Failed to get SDDL' -ForegroundColor Red
                        }
                    }
                }
                $key_update.Close()
            }
            #Restore ownership and access
            write-host "Restoring ownership..."
            $acl = $key.GetAccessControl()
            $acl.SetOwner($administrators)
            $key.SetAccessControl($acl)
            $acl = $key.GetAccessControl()
            $acl.SetAccessRule($readOnly)
            $key.SetAccessControl($acl)
            #Close the key
            write-host "Finished processing"
            $key.Close()
        }
        $item++ | Out-Null
    }

    #Disable privileges for the process
    enable-privilege SeTakeOwnershipPrivilege -Disable | Out-Null
    enable-privilege SeRestorePrivilege -Disable | Out-Null
}

# fix all 10016 events
cls

#Array to avoid reprocessing of same entries
$processed = [System.Collections.ArrayList]@()

#Set entities
$script:trustedInstaller = [Security.Principal.NTAccount]'NT SERVICE\TrustedInstaller'
try {
    $Script:administrators = New-Object System.Security.Principal.NTAccount $("$($ENV:USERDOMAIN)\Domain Admins").trim() -ErrorAction Stop
} catch {
    $script:administrators = New-Object System.Security.Principal.NTAccount (Get-LocalGroup -SID S-1-5-32-544)
}

#Rules for administrators' group
$script:fullAccess = New-Object System.Security.AccessControl.RegistryAccessRule $administrators.Value,'FullControl','ContainerInherit','None','Allow'
$script:readOnly = New-Object System.Security.AccessControl.RegistryAccessRule $administrators.Value,'ReadKey','ContainerInherit','None','Allow'

#Process events
write-host 'Getting events...'
$events = Get-WinEvent -FilterHashTable @{ LogName = 'System'; Id = 10016 }
foreach ($e in $events) {
    $clsid = $e.Properties[3].Value
    $appid = $e.Properties[4].Value
    $user = -join($e.Properties[5].Value, '\', $e.Properties[6].Value)
    if ($user -eq 'NT AUTHORITY\LOCAL SERVICE') {
        $user = 'S-1-5-19'
    } else {
        $user = $e.Properties[7].Value
    }
    $user_alt = $e.Properties[10].Value
    #Process only if something new
    if (-not ($processed.Contains("$clsid$appid$user"))) {
        fixnew $clsid $appid $user $user_alt
        $processed.Add("$clsid$appid$user") | Out-Null
    }
}
write-host 'Processing completed. Reboot recommended.' -ForeGroundColor Yellow