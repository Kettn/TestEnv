function qbvizirpyMSJGiSzewrOHqGNUpmtCVtzSGoRVjZq
{
    [CmdletBinding(PositionalBinding = $fALSE)]
    param(
        [Alias("c")]
        [String[]]
        $CoLLECTIOnMeTHOD = [String[]]@('Default'),

        [Alias("d")]
        [String]
        $DoMAIN,
        
        [Alias("s")]
        [Switch]
        $SEARcHforeST,

        [Switch]
        $StEALtH,

        [String]
        $ldAPFIlTER,

        [String]
        $DIstIngUIshEdnAme,

        [String]
        $compuTeRfILe,

        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $oUTPUTdiReCtorY = $( Get-Location ),

        [ValidateNotNullOrEmpty()]
        [String]
        $oUtPUTPrEFIX,

        [String]
        $CAChEname,

        [Switch]
        $mEmCAchE,

        [Switch]
        $REBUiLdCAcHE,

        [Switch]
        $RANDomfileNaMes,

        [String]
        $zipfiLenaME,
        
        [Switch]
        $NOzIP,
        
        [String]
        $ZipPaSSWORD,
        
        [Switch]
        $TraCkComputerCaLLS,
        
        [Switch]
        $PRETtYpRINT,

        [String]
        $LDapuSernAme,

        [String]
        $ldaPPAsSWorD,

        [string]
        $DOMAINcoNTROLLeR,

        [ValidateRange(0, 65535)]
        [Int]
        $lDapPoRT,

        [Switch]
        $SECurELDAp,
        
        [Switch]
        $DIsableCertvErIFiCATIon,

        [Switch]
        $DisABleSiGnINg,

        [Switch]
        $SkiPpOrTchECK,

        [ValidateRange(50, 5000)]
        [Int]
        $pOrtChECkTiMeOuT = 500,

        [Switch]
        $skIPPASSWORDCheck,

        [Switch]
        $eXClUdEDcS,

        [Int]
        $THrOttLE,

        [ValidateRange(0, 100)]
        [Int]
        $jiTtER,

        [Int]
        $THreADs,

        [Switch]
        $skipreGIstRyLOGGeDon,

        [String]
        $oVeRriDEUSERNAME,

        [String]
        $REaLDNsNAMe,

        [Switch]
        $cOLlecTaLLPRopeRTIes,

        [Switch]
        $lOoP,

        [String]
        $lOOpdurATIoN,

        [String]
        $loOPInTerVal,

        [ValidateRange(500, 60000)]
        [Int]
        $staTUSiNterVAl,
        
        [Alias("v")]
        [ValidateRange(0, 5)]
        [Int]
        $VeRbOsiTy,

        [Alias("h")]
        [Switch]
        $HeLp,

        [Switch]
        $VERSioN
    )

    $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N = New-Object System.Collections.Generic.List[sYSTem.oBJect]

    if ($CoLLECTIOnMeTHOD)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--CollectionMethods");
        foreach ($hzkVTUJuYzd3JA0mxD8bFVIGj0MrAPXrPS411dmsi3mpDZapDz12NzsT83JrhdVQJvhaSdOpVo5M6OM0ar3ptqaGhB1e2slbPiIbmKQB1QU3Ni3OI4nfy3jnuTnG7LHo9xX1YgRQZzFLuWLjQfQegMIORHPXDMS6zB4nBCAz3XBQqA0cjprVRS6z2jXNOEayQbOgGWRyubZrcBmcct2dwMNSe0HewJrhpMKkdJWW3qUu6e7AOUsjjR2rlhKgHVzAs5BbAzWglXVaoqDNPVPYxoWqZvpAHjHlhsteadZm7pf12rWMuCsdHSAdvLtzwkJcBj6nTx4a4wSTT7a3dRnSmKc8uQtP7FwyiOUQOpPSZRww0XjVhScVxlL1zhWP8T4KpJmF6qYenUsS20HegxMZmG9zjg9FTpkd2gsuveroCbTOYKeqc8nlgypAklE3SBZwpiZ5P55TNfbDSK4Qps5iCsRmFX8T7h8GaEP29y8fwJiUc2mndI9r5nsg4mC in $CoLLECTIOnMeTHOD)
        {
            $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($hzkVTUJuYzd3JA0mxD8bFVIGj0MrAPXrPS411dmsi3mpDZapDz12NzsT83JrhdVQJvhaSdOpVo5M6OM0ar3ptqaGhB1e2slbPiIbmKQB1QU3Ni3OI4nfy3jnuTnG7LHo9xX1YgRQZzFLuWLjQfQegMIORHPXDMS6zB4nBCAz3XBQqA0cjprVRS6z2jXNOEayQbOgGWRyubZrcBmcct2dwMNSe0HewJrhpMKkdJWW3qUu6e7AOUsjjR2rlhKgHVzAs5BbAzWglXVaoqDNPVPYxoWqZvpAHjHlhsteadZm7pf12rWMuCsdHSAdvLtzwkJcBj6nTx4a4wSTT7a3dRnSmKc8uQtP7FwyiOUQOpPSZRww0XjVhScVxlL1zhWP8T4KpJmF6qYenUsS20HegxMZmG9zjg9FTpkd2gsuveroCbTOYKeqc8nlgypAklE3SBZwpiZ5P55TNfbDSK4Qps5iCsRmFX8T7h8GaEP29y8fwJiUc2mndI9r5nsg4mC);
        }
    }

    if ($DoMAIN)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--Domain");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($DoMAIN);
    }
    
    if ($SEARcHforeST)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--SearchForest")    
    }

    if ($StEALtH)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--Stealth")
    }

    if ($ldAPFIlTER)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--LdapFilter");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($ldAPFIlTER);
    }

    if ($DIstIngUIshEdnAme)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--DistinguishedName")
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($DIstIngUIshEdnAme)
    }
    
    if ($compuTeRfILe)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--ComputerFile");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($compuTeRfILe);
    }

    if ($oUTPUTdiReCtorY)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--OutputDirectory");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($oUTPUTdiReCtorY);
    }

    if ($oUtPUTPrEFIX)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--OutputPrefix");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($oUtPUTPrEFIX);
    }

    if ($CAChEname)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--CacheName");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($CAChEname);
    }

    if ($KBAJo11ZiKd6u2TxCNZEdtpmWa6yRaug4uISlGrtrZVg9mfutMitCu8zAi3uVWmPbJsWYf3bAlmfOXE4rPVbM9WDDasjIVfgXN5dNQ5CCM48vfY83wChnDRSK6Tm1Nx58A1nBT38PiUqxkbWWZgRrFHoLK6SKcQWeJzdieXvIBWklzsjXwD5BKZyoWECdvlKlGoXP4l4mPmTsg4pzpa7iwuPtdgMFoIe2B2UkHVWubOTvORm4gYU1GW0Sl5bi8d4pOpkgyoQLS9TnwwDhzid4VXjwjBq0KG4RxwKgTK7FPQGlAZH3hlYmTcVnjraV8YMFR1xhdd2u2v1xsPVl70qJiSe0kL0wqVBxsNjgO3iUgBUNo8Yb0QKLummAByHbEdr56VoxFLzOMeVEUOE3rOMXt4CDm7c7fSRJUSZm8FofiHGWBJ5SmCHUG7tAKCKrMFQR7vV1lpjpZvF4MLa2MzLViQTxTBDV1lnrya0z38sGhQTy0nHAuTHYSfp9jxbx1Flg9kifSeIyc7hnjO3Xod1plQcJabi59hSdFQQscqzTo5ajv16X8ef7Ts8DaJDxVmB4y1BCknqwwGSjc2d3BxGsIsCuqUUAMME)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--MemCache");
    }

    if ($REBUiLdCAcHE)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--RebuildCache");
    }

    if ($RANDomfileNaMes)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--RandomFilenames");
    }

    if ($zIpfIlenamE)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--ZipFileName");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($zIpfIlenamE);
    }

    if ($NOzIP)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--NoZip");
    }

    if ($ZipPaSSWORD)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--ZipPassword");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($ZipPaSSWORD)
    }

    if ($TraCkComputerCaLLS)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--TrackComputerCalls")
    }

    if ($PRETtYpRINT)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--PrettyPrint");
    }

    if ($LDapuSernAme)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--LdapUsername");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($LDapuSernAme);
    }

    if ($ldaPPAsSWorD)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--LdapPassword");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($ldaPPAsSWorD);
    }

    if ($DOMAINcoNTROLLeR)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--DomainController");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($DOMAINcoNTROLLeR);
    }
    
    if ($lDapPoRT)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--LdapPort");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($lDapPoRT);
    }
    
    if ($SECurELDAp)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--SecureLdap");
    }
    
    if ($DIsableCertvErIFiCATIon) 
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--DisableCertVerification")    
    }

    if ($DisABleSiGnINg)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--DisableSigning");
    }

    if ($SkiPpOrTchECK)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--SkipPortCheck");
    }

    if ($pOrtChECkTiMeOuT)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--PortCheckTimeout")
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($pOrtChECkTiMeOuT)
    }

    if ($skIPPASSWORDCheck)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--SkipPasswordCheck");
    }

    if ($eXClUdEDcS)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--ExcludeDCs")
    }

    if ($THrOttLE)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--Throttle");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($THrOttLE);
    }

    if ($jiTtER -gt 0)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--Jitter");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($jiTtER);
    }
    
    if ($THreADs)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--Threads")
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($THreADs)
    }

    if ($skipreGIstRyLOGGeDon)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--SkipRegistryLoggedOn")
    }

    if ($oVErrIDEUSerNaMe)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--OverrideUserName")
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($oVeRriDEUSERNAME)
    }
    
    if ($REaLDNsNAMe)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--RealDNSName")
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($REaLDNsNAMe)
    }

    if ($cOLlecTaLLPRopeRTIes)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--CollectAllProperties")
    }

    if ($lOoP)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--Loop")
    }

    if ($lOOpdurATIoN)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--LoopDuration")
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($lOOpdurATIoN)
    }

    if ($loOPInTerVal)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--LoopInterval")
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($loOPInTerVal)
    }

    if ($staTUSiNterVAl)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--StatusInterval")
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($staTUSiNterVAl)
    }

    if ($VeRbOsiTy)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("-v");
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add($VeRbOsiTy);
    }    

    if ($HeLp)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.clear()
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--Help");
    }

    if ($VERSioN)
    {
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.clear();
        $NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.Add("--Version");
    }

    $KyEvpxwBTEyQem19TkUMbzllxkA4I5IqZNVDRwoiMUMQO9anEP72OSUGaawqDi6sIqp3YIyhZK82abYXtfoe1iF10HkOvc2GjCrzDyzRanpuZIyctrhGB4s = [string[]]$NTsIAYib9mJoJx3FhLIxeuP0DeabUoQpcpLZY1Tee6A5oFs0MH2Pf32UCyx2GZotSkzc2qLRjbzzpKHQpIYx8QWh9kvUsTT3fpKjrBRzdFJwIJaNE0sfpnbb3wst3oZDMahpXuMaP4LKmcOMt4d3hAWDCi1TNmBumNY7gCtpFSoId7Khrl5ay0N.ToArray()


	$pOHAPKn0unSi2lUgJxgHXtjY1Cpev5fvnYPFVlIU1IR2xrJvWqAujso70aQzQmEkrHL36ufpXVbxyQuy3FmDVHROn5H9Zmln2KV6EIMPuk9topd1vdOZaTLX3juSOgWPCbRknH2BtdxXOwKav8SrC8jSzhZo3H6dShcihbSEpv7fv6PoVJrO87MGOK4YI2fMc2c6D89myYmGnQAoIjKAVMB4L0JvmxFfBW2crQsh2DXItsRoeUcq7ojAaCHW6K0GdtPWDxlKOVhAgH2KRqj9HaoPLkhYgPKuZs11PcCSHSx9B8VKkAmol9yVfyFZZjFz1sVW5tUWOIGOUy8pDo7GwFH0u5bAFu0SdfXXWiA9sqeN4ul0yfWtP8skmvo6SHkjPKbwiNX = New-Object iO.coMpREsSIon.DEFlaTeStreaM([io.mEMoRYsTReAM][Convert]::FromBase64String($oRF08eQXbhE8XZKBQIEdBGqGbltrp0GwAGphBlpkdzRdbUpQiw7BwcMH8RLb9KZIG5xZ0FqOJqxiXzw4Sn0Y9FhYuoYbdYTr7G5Z4xxE1IJDOk5eCKAkZp2myRFtJA854eFE3orCEnbeCYVnOaEzpIMsTcnPhtGRXl8BBzaLunyZRK4dGHTmXy9WpnVgUpmPfg5KSIylXegP056OcjKvhr0XCvXwVsAjmFj0m6cKPyO1Hvo8SwBDyLdlr9a8dCsPiGpt92rtrcvp1M4JoNRUeKB4glsXBnQRV0gLrLc5qaCpAEkL4hRsfLRwPAil0DYqVO6tjBIsLXsXjB0rTvKjPpcFDOEQa5n2rOYIcSewk55RtPE0YWfoQfk3LGsvC8bYtHLPZArldcd8W9WofgA3QcUREVJpo7JZsM6JEvTdRFzNhzuG7dsbJ2upc8R6d7k6k5795VX8LwqSOCfWN6D),[iO.cOMPressiOn.CompressionmOde]::Decompress)
	$l7wibWrcWQXzt5tVllZrqYWp4PcPWbvNOe3gqkZQPGs72SZlOqqCo9eBVYv9142I0FaHbUG0I0RW7KqSlCbShOWuJNQlUb1ugQbGWn3m7Oql7eBIPGTUfVKCx9DQ0PQpU5uXifgEj2dOZgSVAGDO8nS2iYhcwUFCi1tDnyzSrbAjdvXHWWJQvlXZLmV1yUU3cgTezMQuzntR3PPIR1c92rCjTU9nIaEcuD64nXGJ8xN0ji6Oeq3f3HXsU70mQ555mw4VfM8Ookgl9h057eyC1ZOXpNxZkrH3LzO8T8aD5Hq0XPb0MGRTI9FQa8ws2XBHfuE6otmS1bjQbVowGvjErWbZ3Eztovcn6ptzQkwyHUaRQoSSA0Bv1YIianqCtjz9xgpYbwuuqRk5ehQXglTawh7bZ3BTiCi8deamFMFTcC8wdvsiSAB39vJSX232UPnVXue4QIxI9QWzf3Zmw5HKhtPcJBVDupVvcfEgUM9Onb8uFpW09uDUCqH1CsNspMDmgIyZHYZZ3rEW9p2nvtGOZMZxPl5AVlD6TeXIGpIOCMDU9Bx0f6GroqBYjEpaAJVbDxykDa2fjJBYozPdGrGZRMJ7TwO1b51KHLn0QgPrhmAfd4ImgfDtAQ6c8mqA6qBYNrXWuyFryVN0TDRHBd0iWTV2SvBjvXNsrKbky2rQvjRsZvFi2HMJVdzsW46431t0gDuybB2BvmGK80hRh0Wo54iuJTzQlRLXOcOadIyLADXXmH1mZwWspON2ef9sy1gov6Nt44jblnDVXjZlGGqunggU = New-Object bYtE[](1051648)
	$pOHAPKn0unSi2lUgJxgHXtjY1Cpev5fvnYPFVlIU1IR2xrJvWqAujso70aQzQmEkrHL36ufpXVbxyQuy3FmDVHROn5H9Zmln2KV6EIMPuk9topd1vdOZaTLX3juSOgWPCbRknH2BtdxXOwKav8SrC8jSzhZo3H6dShcihbSEpv7fv6PoVJrO87MGOK4YI2fMc2c6D89myYmGnQAoIjKAVMB4L0JvmxFfBW2crQsh2DXItsRoeUcq7ojAaCHW6K0GdtPWDxlKOVhAgH2KRqj9HaoPLkhYgPKuZs11PcCSHSx9B8VKkAmol9yVfyFZZjFz1sVW5tUWOIGOUy8pDo7GwFH0u5bAFu0SdfXXWiA9sqeN4ul0yfWtP8skmvo6SHkjPKbwiNX.Read($l7wibWrcWQXzt5tVllZrqYWp4PcPWbvNOe3gqkZQPGs72SZlOqqCo9eBVYv9142I0FaHbUG0I0RW7KqSlCbShOWuJNQlUb1ugQbGWn3m7Oql7eBIPGTUfVKCx9DQ0PQpU5uXifgEj2dOZgSVAGDO8nS2iYhcwUFCi1tDnyzSrbAjdvXHWWJQvlXZLmV1yUU3cgTezMQuzntR3PPIR1c92rCjTU9nIaEcuD64nXGJ8xN0ji6Oeq3f3HXsU70mQ555mw4VfM8Ookgl9h057eyC1ZOXpNxZkrH3LzO8T8aD5Hq0XPb0MGRTI9FQa8ws2XBHfuE6otmS1bjQbVowGvjErWbZ3Eztovcn6ptzQkwyHUaRQoSSA0Bv1YIianqCtjz9xgpYbwuuqRk5ehQXglTawh7bZ3BTiCi8deamFMFTcC8wdvsiSAB39vJSX232UPnVXue4QIxI9QWzf3Zmw5HKhtPcJBVDupVvcfEgUM9Onb8uFpW09uDUCqH1CsNspMDmgIyZHYZZ3rEW9p2nvtGOZMZxPl5AVlD6TeXIGpIOCMDU9Bx0f6GroqBYjEpaAJVbDxykDa2fjJBYozPdGrGZRMJ7TwO1b51KHLn0QgPrhmAfd4ImgfDtAQ6c8mqA6qBYNrXWuyFryVN0TDRHBd0iWTV2SvBjvXNsrKbky2rQvjRsZvFi2HMJVdzsW46431t0gDuybB2BvmGK80hRh0Wo54iuJTzQlRLXOcOadIyLADXXmH1mZwWspON2ef9sy1gov6Nt44jblnDVXjZlGGqunggU, 0, 1051648) | Out-Null
	$ieCNGZytiOsxESq0ySO96H22kFCnbdb6bqrYizLyV2ighqwzLB6KdkrJTMrqEF7n90mcfhMSG2YfUvkx8Q4Dra9LkWFc5Ex3B2MefgCjHUh7KaITP7sipoRYeO9qKa4Zz22LjQOssLAt4PKh4rccqhEDk17mZSvDygMFet3cNd89oZruuhqwMX6U8N9lRoFQrbkckEeO0n9IesQ07ikNqN98Ah6NCNUHyAWYH5I1lArlGkw1CFBdFr7xtpyRuEnFGcJ0JaybwCyeIZv8am2ROfg8lFEfkYrT9axpZBAK1Ue1UIGZFjwwsqx6tD3LQFXxIz4jTG0bukX4oSpXnaiwRoZTXSWTka3zpBSuT5kQ3wFqrPLLxbDy7Mmy0Ne4BIvauhzq2U2cgFogxPednZuYvWc3chU2jaaGzSuXi1ibvAGyzIvHYt03fpwCrqs8OLbnLWnToJpmwaBDyZqKpxhIF9jZBr6r3XBOBxcWuLydvzL9bwkdE537UKBJGqFU2Oq3jgGd1YuwxYWTPkA3IAxtSgvIMxNAkA5yLJNxLz2km6zuMKCxPRiul4qIS0oKHbwkpkDcfP5ly0rTejyF5mUPowjXXkNNQ2UA4wALCDFaK7ilgWdf75y1J0wGpUiTV4AU0cWyVBGYRlwmKeB4UKL3ijA7HYyqEP22DPp7IuMfkqrfePKO6LHJWW6HsKizepyi89yIbpBj8LucyQfmjISOCk2Wtj7IK6yfjBuLGPQ3ui7fH1XbutK3xZNcJvUyoVSjy9KmmGVkFSGFloQn0f8TBA7ZJDUHn5StZGwjPLA5kcv4xUklfjJVy1ygO265SDJCG5HYn0vmCSO7RuwlUasKn3tdQBa3rPHI38hIz4gbCJUFSFXYmyft8NXkT8MkOiiwXhIEIVVeO4nTcGFVCP7f62LXxn92hqqOAOnPNgl6ktHrHg00XOdjOCyN9rlfnvWCd3lEck65c3meK2v0VN = [rEfLectIon.ASSEmBly]::Load($l7wibWrcWQXzt5tVllZrqYWp4PcPWbvNOe3gqkZQPGs72SZlOqqCo9eBVYv9142I0FaHbUG0I0RW7KqSlCbShOWuJNQlUb1ugQbGWn3m7Oql7eBIPGTUfVKCx9DQ0PQpU5uXifgEj2dOZgSVAGDO8nS2iYhcwUFCi1tDnyzSrbAjdvXHWWJQvlXZLmV1yUU3cgTezMQuzntR3PPIR1c92rCjTU9nIaEcuD64nXGJ8xN0ji6Oeq3f3HXsU70mQ555mw4VfM8Ookgl9h057eyC1ZOXpNxZkrH3LzO8T8aD5Hq0XPb0MGRTI9FQa8ws2XBHfuE6otmS1bjQbVowGvjErWbZ3Eztovcn6ptzQkwyHUaRQoSSA0Bv1YIianqCtjz9xgpYbwuuqRk5ehQXglTawh7bZ3BTiCi8deamFMFTcC8wdvsiSAB39vJSX232UPnVXue4QIxI9QWzf3Zmw5HKhtPcJBVDupVvcfEgUM9Onb8uFpW09uDUCqH1CsNspMDmgIyZHYZZ3rEW9p2nvtGOZMZxPl5AVlD6TeXIGpIOCMDU9Bx0f6GroqBYjEpaAJVbDxykDa2fjJBYozPdGrGZRMJ7TwO1b51KHLn0QgPrhmAfd4ImgfDtAQ6c8mqA6qBYNrXWuyFryVN0TDRHBd0iWTV2SvBjvXNsrKbky2rQvjRsZvFi2HMJVdzsW46431t0gDuybB2BvmGK80hRh0Wo54iuJTzQlRLXOcOadIyLADXXmH1mZwWspON2ef9sy1gov6Nt44jblnDVXjZlGGqunggU)
	$sOmiajSfmroiub5WOUuIJlmOfdpoUc2w3rBW3UqMOmSiVDy4fTrgFHcleFQjJSrhGlRBsAoLpcarOA6zMMt00gN48JugDWOTjWF4uzAsI1Pt49OdG0KLpmxIdqa8jf6ZohrjDXSkGBm6imRscvOKgUodiIraMy4IvHtCyXaVYeo0fwmMYO7mQgdUGaegM485Lhs5GaJTyLbbbJwxVdkUdyvswY1KfNYZ1f8pUgw7n8uqnKJOIQXC6JusV0oCRfuiEaAT8al3EwozO476iUXXDLY9cZD = [refLeCTion.bIndIngflAgS] "Public,Static"
	$sKrwRHXgjaSpPg5JR4hSs3o5seUmOw6DxbQTZHTUmDR1gzEl9lACndZYCyLq0I65Fus4i6Y8KkNkJqgcJ8buQUul0JOhRdSpnYsdDWXXoeyxIECoYaaAytsMqHSXGMtG4SC2600rbYvIpOWITqraLtF5uiqsCIj76bMl0OdYmJBVySPK5Fjwqrq9VaqASc7uyoF8lCwO4cwBl5L50JkVqIqaJjVigXR6S0oBRwBp3Ggv6myZ7jp5MXRmPrJ7nzUsAimvbP1jpathU62upCyvn4SafJADm4JhcCw3quCQYodLE7XKcHc8WGxr9QJhWKN7BR0TCctGhQyAc77aHhTi8iCYExW9wyHI6tOaBiPuRTlrp2r6yA8BGz8fajTVyUcUri3hhhXoNd2Xc6eadqZqi379haFH6AdwXcTAmnxCfF6UHEcZfi1iSZGd7RTjxtxN0BBXhaoaMhXNVyzXDSai2vGaop58wHEYHxLZvM043lACebE9AfJf6fi0VMXuR7BTQcSLpkl3GDFTuirx9OlxIKVuYs0NiiDd8UPW = @()
	$ieCNGZytiOsxESq0ySO96H22kFCnbdb6bqrYizLyV2ighqwzLB6KdkrJTMrqEF7n90mcfhMSG2YfUvkx8Q4Dra9LkWFc5Ex3B2MefgCjHUh7KaITP7sipoRYeO9qKa4Zz22LjQOssLAt4PKh4rccqhEDk17mZSvDygMFet3cNd89oZruuhqwMX6U8N9lRoFQrbkckEeO0n9IesQ07ikNqN98Ah6NCNUHyAWYH5I1lArlGkw1CFBdFr7xtpyRuEnFGcJ0JaybwCyeIZv8am2ROfg8lFEfkYrT9axpZBAK1Ue1UIGZFjwwsqx6tD3LQFXxIz4jTG0bukX4oSpXnaiwRoZTXSWTka3zpBSuT5kQ3wFqrPLLxbDy7Mmy0Ne4BIvauhzq2U2cgFogxPednZuYvWc3chU2jaaGzSuXi1ibvAGyzIvHYt03fpwCrqs8OLbnLWnToJpmwaBDyZqKpxhIF9jZBr6r3XBOBxcWuLydvzL9bwkdE537UKBJGqFU2Oq3jgGd1YuwxYWTPkA3IAxtSgvIMxNAkA5yLJNxLz2km6zuMKCxPRiul4qIS0oKHbwkpkDcfP5ly0rTejyF5mUPowjXXkNNQ2UA4wALCDFaK7ilgWdf75y1J0wGpUiTV4AU0cWyVBGYRlwmKeB4UKL3ijA7HYyqEP22DPp7IuMfkqrfePKO6LHJWW6HsKizepyi89yIbpBj8LucyQfmjISOCk2Wtj7IK6yfjBuLGPQ3ui7fH1XbutK3xZNcJvUyoVSjy9KmmGVkFSGFloQn0f8TBA7ZJDUHn5StZGwjPLA5kcv4xUklfjJVy1ygO265SDJCG5HYn0vmCSO7RuwlUasKn3tdQBa3rPHI38hIz4gbCJUFSFXYmyft8NXkT8MkOiiwXhIEIVVeO4nTcGFVCP7f62LXxn92hqqOAOnPNgl6ktHrHg00XOdjOCyN9rlfnvWCd3lEck65c3meK2v0VN.GetType("Costura.AssemblyLoader", $fALSE).GetMethod("Attach", $sOmiajSfmroiub5WOUuIJlmOfdpoUc2w3rBW3UqMOmSiVDy4fTrgFHcleFQjJSrhGlRBsAoLpcarOA6zMMt00gN48JugDWOTjWF4uzAsI1Pt49OdG0KLpmxIdqa8jf6ZohrjDXSkGBm6imRscvOKgUodiIraMy4IvHtCyXaVYeo0fwmMYO7mQgdUGaegM485Lhs5GaJTyLbbbJwxVdkUdyvswY1KfNYZ1f8pUgw7n8uqnKJOIQXC6JusV0oCRfuiEaAT8al3EwozO476iUXXDLY9cZD).Invoke($null, @())
	$ieCNGZytiOsxESq0ySO96H22kFCnbdb6bqrYizLyV2ighqwzLB6KdkrJTMrqEF7n90mcfhMSG2YfUvkx8Q4Dra9LkWFc5Ex3B2MefgCjHUh7KaITP7sipoRYeO9qKa4Zz22LjQOssLAt4PKh4rccqhEDk17mZSvDygMFet3cNd89oZruuhqwMX6U8N9lRoFQrbkckEeO0n9IesQ07ikNqN98Ah6NCNUHyAWYH5I1lArlGkw1CFBdFr7xtpyRuEnFGcJ0JaybwCyeIZv8am2ROfg8lFEfkYrT9axpZBAK1Ue1UIGZFjwwsqx6tD3LQFXxIz4jTG0bukX4oSpXnaiwRoZTXSWTka3zpBSuT5kQ3wFqrPLLxbDy7Mmy0Ne4BIvauhzq2U2cgFogxPednZuYvWc3chU2jaaGzSuXi1ibvAGyzIvHYt03fpwCrqs8OLbnLWnToJpmwaBDyZqKpxhIF9jZBr6r3XBOBxcWuLydvzL9bwkdE537UKBJGqFU2Oq3jgGd1YuwxYWTPkA3IAxtSgvIMxNAkA5yLJNxLz2km6zuMKCxPRiul4qIS0oKHbwkpkDcfP5ly0rTejyF5mUPowjXXkNNQ2UA4wALCDFaK7ilgWdf75y1J0wGpUiTV4AU0cWyVBGYRlwmKeB4UKL3ijA7HYyqEP22DPp7IuMfkqrfePKO6LHJWW6HsKizepyi89yIbpBj8LucyQfmjISOCk2Wtj7IK6yfjBuLGPQ3ui7fH1XbutK3xZNcJvUyoVSjy9KmmGVkFSGFloQn0f8TBA7ZJDUHn5StZGwjPLA5kcv4xUklfjJVy1ygO265SDJCG5HYn0vmCSO7RuwlUasKn3tdQBa3rPHI38hIz4gbCJUFSFXYmyft8NXkT8MkOiiwXhIEIVVeO4nTcGFVCP7f62LXxn92hqqOAOnPNgl6ktHrHg00XOdjOCyN9rlfnvWCd3lEck65c3meK2v0VN.GetType("Sharphound.Program").GetMethod("InvokeSharpHound").Invoke($null, @(,$KyEvpxwBTEyQem19TkUMbzllxkA4I5IqZNVDRwoiMUMQO9anEP72OSUGaawqDi6sIqp3YIyhZK82abYXtfoe1iF10HkOvc2GjCrzDyzRanpuZIyctrhGB4s))
}