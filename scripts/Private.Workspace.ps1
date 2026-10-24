# Requires Windows PowerShell 5.1 or PowerShell 7 on Windows. No ACL repair or adoption.
function Get-ToolkitPrivatePrincipals {
    if([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT){throw 'Private workspace requires supported Windows security APIs; hold without creating files.'}
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try {$user=$identity.User;if($null -eq $user){throw 'Private workspace cannot establish the current token owner; hold.'}}
    finally {$identity.Dispose()}
    $system=[Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid,$null)
    $administrators=[Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
    $allowed=[Collections.Generic.Dictionary[string,Security.Principal.SecurityIdentifier]]::new([StringComparer]::Ordinal)
    foreach($principal in @($user,$system,$administrators)){if(-not $allowed.ContainsKey($principal.Value)){$allowed.Add($principal.Value,$principal)}}
    return [pscustomobject]@{User=$user;Allowed=$allowed}
}
function Get-ToolkitPrivateAclExtension {
    $type='System.IO.FileSystemAclExtensions' -as [type]
    if($null -eq $type){throw 'Required atomic Windows ACL creation capability is unavailable; hold without creating files.'}
    return $type
}
function Get-ToolkitPrivateSecurity([string]$Path,[bool]$Directory) {
    $sections=[Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
    $info=if($Directory){[IO.DirectoryInfo]::new($Path)}else{[IO.FileInfo]::new($Path)}
    $method=$info.GetType().GetMethod('GetAccessControl',[type[]]@([Security.AccessControl.AccessControlSections]))
    try {
        if($null -ne $method){return $info.GetAccessControl($sections)}
        $extension=Get-ToolkitPrivateAclExtension
        $method=$extension.GetMethod('GetAccessControl',[type[]]@($info.GetType(),[Security.AccessControl.AccessControlSections]))
        if($null -eq $method){throw 'Required Windows ACL read capability is unavailable.'}
        return $extension::GetAccessControl($info,$sections)
    } catch {throw 'Private workspace security cannot be verified; hold without changing permissions.'}
}
function Assert-ToolkitPrivateObject([string]$Path,[bool]$Directory,$Principals,[bool]$NamespaceRoot=$false) {
    $attributes=[IO.File]::GetAttributes($Path)
    if(($attributes -band [IO.FileAttributes]::ReparsePoint) -or (($attributes -band [IO.FileAttributes]::Directory) -ne 0) -ne $Directory){throw 'Private workspace reparse point or wrong object type refused.'}
    $security=Get-ToolkitPrivateSecurity $Path $Directory
    $raw=[Security.AccessControl.RawSecurityDescriptor]::new($security.GetSecurityDescriptorBinaryForm(),0)
    if($null -eq $raw.Owner -or $raw.Owner.Value -cne $Principals.User.Value){throw 'Private workspace owner differs from the current token user; no adoption or permission repair.'}
    $flags=$raw.ControlFlags
    if(($flags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -eq 0 -or $null -eq $raw.DiscretionaryAcl -or ($NamespaceRoot -and ($flags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0)){throw 'Private workspace requires a present protected namespace DACL; no permission repair.'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $inherit=[int][Security.AccessControl.AceFlags]::ContainerInherit -bor [int][Security.AccessControl.AceFlags]::ObjectInherit
    foreach($ace in $raw.DiscretionaryAcl) {
        if($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback -or $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or $ace.OpaqueLength -ne 0){throw 'Private workspace contains an unsupported access rule; hold without changing permissions.'}
        $sid=$ace.SecurityIdentifier.Value
        $expected=if($Directory){$inherit}else{[Security.AccessControl.AceFlags]::None}
        $actual=[int]$ace.AceFlags -band (-bnot [int][Security.AccessControl.AceFlags]::Inherited)
        if(-not $Principals.Allowed.ContainsKey($sid) -or -not $seen.Add($sid) -or $ace.AccessMask -ne [int][Security.AccessControl.FileSystemRights]::FullControl -or $actual -ne $expected -or ($NamespaceRoot -and ([int]$ace.AceFlags -band [int][Security.AccessControl.AceFlags]::Inherited))){throw 'Private workspace access is not restricted to the current user and trusted Windows administrators; no permission repair.'}
    }
    if($seen.Count -ne $Principals.Allowed.Count){throw 'Private workspace lacks required owner or trusted administrator control; hold.'}
}
function Assert-ToolkitPrivateWorkspace([string]$Path) {
    $principals=Get-ToolkitPrivatePrincipals
    Assert-ToolkitPrivateObject $Path $true $principals $true
    # Verify metadata before opening private contents. Explicit child ACLs can weaken a private parent.
    $pending=[Collections.Generic.Stack[string]]::new();$pending.Push($Path)
    while($pending.Count -gt 0) {
        $directory=$pending.Pop()
        foreach($child in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $attributes=[IO.File]::GetAttributes($child)
            if($attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Private workspace reparse point refused.'}
            $isDirectory=($attributes -band [IO.FileAttributes]::Directory) -ne 0
            Assert-ToolkitPrivateObject $child $isDirectory $principals
            if($isDirectory){$pending.Push($child)}
        }
    }
}
function New-ToolkitPrivateDirectory([string]$Path) {
    $principals=Get-ToolkitPrivatePrincipals
    if(Test-Path -LiteralPath $Path){Assert-ToolkitPrivateWorkspace $Path;return}
    # The parent may be shared; every parent must already exist and be an ordinary directory.
    $parent=[IO.Directory]::GetParent([IO.Path]::GetFullPath($Path))
    if($null -eq $parent){throw 'Private workspace requires an existing ordinary parent.'}
    $ancestor=$parent
    while($null -ne $ancestor){$attributes=[IO.File]::GetAttributes($ancestor.FullName);if(($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or ($attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Private workspace parent is missing, redirected or not a directory.'};$ancestor=$ancestor.Parent}
    $security=[Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($principals.User)
    $security.SetAccessRuleProtection($true,$false)
    $inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach($principal in $principals.Allowed.Values){$rule=[Security.AccessControl.FileSystemAccessRule]::new($principal,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow);$security.AddAccessRule($rule)}
    $method=[IO.Directory].GetMethod('CreateDirectory',[type[]]@([string],[Security.AccessControl.DirectorySecurity]))
    if($null -ne $method){$null=[IO.Directory]::CreateDirectory($Path,$security)}
    else {
        $extension=Get-ToolkitPrivateAclExtension
        $method=$extension.GetMethod('Create',[type[]]@([IO.DirectoryInfo],[Security.AccessControl.DirectorySecurity]))
        if($null -eq $method){throw 'Required atomic Windows directory ACL creation is unavailable; hold without creating files.'}
        $extension::Create([IO.DirectoryInfo]::new($Path),$security)
    }
    # Atomic creation APIs may return an object created by a competing process. Never adopt or repair it.
    Assert-ToolkitPrivateWorkspace $Path
}
function New-ToolkitPrivateFileStream {
    param([string]$Path,[IO.FileAccess]$Access=[IO.FileAccess]::Write,[IO.FileShare]$Share=[IO.FileShare]::None,[IO.FileOptions]$Options=[IO.FileOptions]::None)
    $principals=Get-ToolkitPrivatePrincipals
    $parent=[IO.Directory]::GetParent([IO.Path]::GetFullPath($Path))
    if($null -eq $parent){throw 'Private file requires an existing private parent directory.'}
    Assert-ToolkitPrivateObject $parent.FullName $true $principals
    $ancestor=$parent
    while($null -ne $ancestor){$attributes=[IO.File]::GetAttributes($ancestor.FullName);if(($attributes -band [IO.FileAttributes]::Directory) -eq 0 -or ($attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Private file parent is missing, redirected or not a directory.'};$ancestor=$ancestor.Parent}
    if($Access -eq [IO.FileAccess]::Write){$rights=[Security.AccessControl.FileSystemRights]::Write}
    elseif($Access -eq [IO.FileAccess]::ReadWrite){$rights=[Security.AccessControl.FileSystemRights]::Read -bor [Security.AccessControl.FileSystemRights]::Write}
    else {throw 'Private create-new stream requires write or read/write access.'}
    $security=[Security.AccessControl.FileSecurity]::new()
    $security.SetOwner($principals.User)
    $security.SetAccessRuleProtection($true,$false)
    foreach($principal in $principals.Allowed.Values){$security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($principal,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))}
    $signature=[type[]]@([string],[IO.FileMode],[Security.AccessControl.FileSystemRights],[IO.FileShare],[int],[IO.FileOptions],[Security.AccessControl.FileSecurity])
    $constructor=[IO.FileStream].GetConstructor($signature)
    $stream=$null
    try {
        if($null -ne $constructor){$stream=[IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,$rights,$Share,4096,$Options,$security)}
        else {
            $extension=Get-ToolkitPrivateAclExtension
            $signature[0]=[IO.FileInfo]
            if($null -eq $extension.GetMethod('Create',$signature)){throw 'Required atomic Windows file ACL creation is unavailable; hold without creating files.'}
            $stream=$extension::Create([IO.FileInfo]::new($Path),[IO.FileMode]::CreateNew,$rights,$Share,4096,$Options,$security)
        }
        # Token default owners may be an enabled owner-group. Verify explicit TokenUser ownership before bytes.
        Assert-ToolkitPrivateObject $Path $false $principals
        return $stream
    } catch {if($null -ne $stream){$stream.Dispose()};throw}
}
