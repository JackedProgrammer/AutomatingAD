##########################################
##Automating AD
##Date: June 19 2021
##By: Richard Therrien (JackedProgrammer)
##Automates Active Directory using PowerShell and a CSV file
##########################################


#1. Load in the csv file for employees
function Get-EmployeeFromCsv{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string]$Delimiter,
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap
    )

    try{
        $SyncProperties=$SyncFieldMap.GetEnumerator()
        $Properties=ForEach($Property in $SyncProperties){
            @{Name=$Property.Value;Expression=[scriptblock]::Create("`$_.$($Property.Key)")}
        }

        Import-Csv -Path $FilePath -Delimiter $Delimiter | Select-Object -Property $Properties
    }catch{
        Write-Error $_.Exception.Messge
    }
}

#2. Load in the employees already in AD
function Get-EmployeesFromAD{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap,
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$UniqueID
    )

    try{
        Get-ADUser -Filter {$UniqueID -like "*"} -Server $Domain -Properties @($SyncFieldMap.Values) 
    }catch{
        Write-Error -Message $_.Exception.Message
    }
}

#3. Compare those
function Compare-Users{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap,
        [Parameter(Mandatory)]
        [string]$UniqueID,
        [Parameter(Mandatory)]
        [string]$CSVFilePath,
        [Parameter()]
        [string]$Delimiter=",",
        [Parameter(Mandatory)]
        [string]$Domain
    )

    try{
        $CSVUsers=Get-EmployeeFromCsv -FilePath $CsvFilePath -Delimiter $Delimiter -SyncFieldMap $SyncFieldMap
        $ADUsers=Get-EmployeesFromAD -SyncFieldMap $SyncFieldMap -UniqueID $UniqueId -Domain $Domain

        Compare-Object -ReferenceObject $ADUsers -DifferenceObject $CSVUsers -Property $UniqueId -IncludeEqual
    }catch{
        Write-Error -Message $_.Exception.Message
    }
}

#Get the new users
#Get the synced users
#Get removed users
function Get-UserSyncData{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap,
        [Parameter(Mandatory)]
        [string]$UniqueID,
        [Parameter(Mandatory)]
        [string]$CSVFilePath,
        [Parameter()]
        [string]$Delimiter=",",
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$OUProperty
    )

    try{
        $CompareData=Compare-Users -SyncFieldMap $SyncFieldMap -UniqueID $UniqueId -CSVFilePath $CsvFilePath -Delimiter $Delimiter -Domain $Domain
        $NewUsersID=$CompareData | where SideIndicator -eq "=>"
        $SyncedUsersID=$CompareData | where SideIndicator -eq "=="
        $RemovedUsersID=$CompareData | where SideIndicator -eq "<="

        $NewUsers=Get-EmployeeFromCsv -FilePath $CsvFilePath -Delimiter $Delimiter -SyncFieldMap $SyncFieldMap | where $UniqueId -In $NewUsersID.$UniqueId
        $SyncedUsers=Get-EmployeeFromCsv -FilePath $CsvFilePath -Delimiter $Delimiter -SyncFieldMap $SyncFieldMap | where $UniqueId -In $SyncedUsersID.$UniqueId
        $RemovedUsers=Get-EmployeesFromAD -SyncFieldMap $SyncFieldMap -Domain $Domain -UniqueID $UniqueId | where $UniqueId -In $RemovedUsersID.$UniqueId

        @{
            New=$NewUsers
            Synced=$SyncedUsers
            Removed=$RemovedUsers
            Domain=$Domain
            UniqueID=$UniqueID
            OUProperty=$OUProperty
        }
    }catch{
        Write-Error $_.Exception.Message
    }

}

function New-UserName{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$GivenName,
        [Parameter(Mandatory)]
        [string]$Surname,
        [Parameter(Mandatory)]
        [string]$Domain
    )

    try{
        [RegEx]$Pattern="\s|-|'"
        $index=1

        do{
            $Username="$Surname$($GivenName.Substring(0,$index))" -replace $Pattern,""
            $index++
        }while((Get-ADUser -Filter "SamAccountName -like '$Username'" -Server $Domain) -and ($Username -notlike "$Surname$GivenName"))

        if(Get-ADUser -Filter "SamAccountName -like '$Username'" -Server $Domain){
            throw "No usernames available for this user!"
        }else{
            $Username
        }
    }catch{
        Write-Error -Message $_.Exception.Message
    }
}

function Validate-OU{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap,
        [Parameter(Mandatory)]
        [string]$CSVFilePath,
        [Parameter()]
        [string]$Delimiter=",",
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter()]
        [string]$OUProperty
    )

    try{
        $OUNames=Get-EmployeeFromCsv -FilePath $CsvFilePath -Delimiter "," -SyncFieldMap $SyncFieldMap `
        | Select -Unique -Property $OUProperty

        foreach($OUName in $OUNames){
            $OUName=$OUName.$OUProperty
            if(-not (Get-ADOrganizationalUnit -Filter "name -eq '$OUName'" -Server $Domain)){
                New-ADOrganizationalUnit -Name $OUName -Server $Domain -ProtectedFromAccidentalDeletion $false 
            }
        }
    }catch{
        Write-Error -Message $_.Exception.Message
    }
}

function Create-NewUsers{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$UserSyncData
    )

    try{
        $NewUsers=$UserSyncData.New

        foreach($NewUser in $NewUsers){
            Write-Verbose "Creating user : {$($NewUser.givenname) $($Newuser.surname)}"
            $Username=New-UserName -GivenName $NewUser.GivenName -Surname $Newuser.Surname -Domain $UserSyncData.Domain
            Write-Verbose "Creating user : {$($NewUser.givenname) $($Newuser.surname)} with username : {$Username}"
            if(-not ($OU=Get-ADOrganizationalUnit -Filter "name -eq '$($NewUser.$($UserSyncData.OUProperty))'" -Server $UserSyncData.Domain)){
                throw "The organizational unit {$($NewUser.$($UserSyncData.OUProperty))}"
            }
            Write-Verbose "Creating user : {$($NewUser.givenname) $($Newuser.surname)} with username : {$Username}, {$ou)}"

            Add-Type -AssemblyName 'System.Web'
            $Password=[System.Web.Security.Membership]::GeneratePassword((Get-Random -Minimum 12 -Maximum 15),3)
            $SecuredPassword=ConvertTo-SecureString -String $Password -AsPlainText -Force

            $NewADUserParams=@{
                EmployeeID=$NewUser.EmployeeID
                GivenName=$NewUser.GivenName
                Surname=$NewUser.Surname
                Name=$Username
                SamAccountName=$Username
                UserPrincipalName="$Username@$($Usersyncdata.Domain)"
                AccountPassword=$SecuredPassword
                ChangePasswordAtLogon=$true
                Enabled=$true
                Title=$NewUser.Title
                Department=$NewUser.Department
                Office=$NewUser.Office
                Path=$OU.DistinguishedName
                Confirm=$false
                Server=$UserSyncData.Domain
            }

            New-ADUser @NewADUserParams
            Write-Verbose "Created user: {$($NewUser.Givenname) $($NewUser.Surname)} EmpID: {$($NewUser.EmployeeID) Username: {$Username} Password: {$Password}"
        }
    }catch{
        Write-Error $_.Exception.Message
    }
}

function Check-UserName{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$GivenName,
        [Parameter(Mandatory)]
        [string]$Surname,
        [Parameter(Mandatory)]
        [string]$CurrentUserName,
        [Parameter(Mandatory)]
        [string]$Domain
    )

    try{
        [RegEx]$Pattern="\s|-|'"
        $index=1

        do{
            $Username="$Surname$($GivenName.Substring(0,$index))" -replace $Pattern,""
            $index++
        }while((Get-ADUser -Filter "SamAccountName -like '$Username'" -Server $Domain) -and ($Username -notlike "$Surname$GivenName") -and ($Username -notlike $CurrentUserName))

        if((Get-ADUser -Filter "SamAccountName -like '$Username'" -Server $Domain) -and ($Username -notlike $CurrentUserName)){
            throw "No usernames available for this user!"
        }else{
            $Username
        }
    }catch{
        Write-Error -Message $_.Exception.Message
    }
}

#Check synced users
    #Change OU
    #Check-username
    #update any other fields, position, office
function Sync-ExistingUsers{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$UserSyncData,
        [Parameter(Mandatory)]
        [hashtable]$SyncFieldMap
    )

    try{
        $SyncedUsers=$UserSyncData.Synced

        foreach($SyncedUser in $SyncedUsers){
            Write-Verbose "Loading data for $($SyncedUser.givenname) $($synceduser.surname)"
            $ADUser=Get-ADUser -Filter "$($UserSyncData.UniqueID) -eq $($SyncedUser.$($UserSyncData.UniqueID))" -Server $UserSyncData.Domain -Properties *
            if(-not ($OU=Get-ADOrganizationalUnit -Filter "name -eq '$($SyncedUser.$($UserSyncData.OUProperty))'" -Server $UserSyncData.Domain)){
                    throw "The organizational unit {$($SyncedUser.$($UserSyncData.OUProperty))}"
            }
            Write-Verbose "User is currently in $($ADUser.distinguishedname) but should be in $OU"
            if(($ADUser.DistinguishedName.split(",")[1..$($ADUser.DistinguishedName.Length)] -join ",") -ne ($OU.DistinguishedName)){
                Write-Verbose "OU needs to be changed"
                Move-ADObject -Identity $ADUser -TargetPath $OU -Server $UserSyncData.Domain
            }

            $ADUser=Get-ADUser -Filter "$($UserSyncData.UniqueID) -eq $($SyncedUser.$($UserSyncData.UniqueID))" -Server $UserSyncData.Domain -Properties *

            $Username=Check-UserName -GivenName $SyncedUser.GivenName -Surname $SyncedUser.Surname -CurrentUserName $ADUser.SamAccountName -Domain $UserSyncData.Domain

            if($ADUser.SamAccountName -notlike $Username){
                Write-Verbose "Username needs to be changed"
                Set-ADUser -Identity $ADUser -Replace @{userprincipalname="$Username@$($UserSyncData.Domain)"} -Server $UserSyncData.Domain
                Set-ADUser -Identity $ADUser -Replace @{samaccountname="$Username"} -Server $UserSyncData.Domain
                Rename-ADObject -Identity $ADUser -NewName $Username -Server $UserSyncData.Domain
            }

            $SetADUserParams=@{
                Identity=$Username
                Server=$UserSyncData.Domain
            }

            foreach($Property in $SyncFieldMap.Values){
                $SetADUserParams[$Property]=$SyncedUser.$Property
            }

            Set-ADUser @SetADUserParams
        }
    }catch{
        Write-Error -Message $_.Exception.Message
    }
}

#Check removed users, then disable them
function Remove-Users{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [hashtable]$UserSyncData,
        [Parameter()]
        [int]$KeepDisabledForDays=7
    )

    try{
        $RemovedUsers=$UserSyncData.Removed

        foreach($RemovedUser in $RemovedUsers){
            Write-Verbose "Fetching data for $($RemovedUser.Name)"
            $ADUser=Get-ADUser $RemovedUser -Properties * -Server $UserSyncData.Domain
            if($ADUser.Enabled -eq $true){
                Write-Verbose "Disabling user $($ADUser.Name)"
                Set-ADUser -Identity $ADUser -Enabled $false -AccountExpirationDate (Get-date).AddDays($KeepDisabledForDays) -Server $UserSyncData.Domain -Confirm:$false
            }else{
                if($ADUser.AccountExpirationDate -lt (get-date)){
                    Write-Verbose "Deleting account $($Aduser.name)"
                    Remove-ADUser -Identity $ADUser -Server $UserSyncData.Domain -Confirm:$false
                }else{
                    Write-Verbose "Account $($ADUser.name) is still within the retention period"
                }
            }
        }
    }catch{
        Write-Error -Message $_.Exception.Message
    }
}

$SyncFieldMap=@{
    EmployeeID="EmployeeID"
    FirstName="GivenName"
    LastName="SurName"
    Title="Title"
    Department="Department"
    Office="Office"
}

$CsvFilePath="C:\Data\Employees.csv"
$Delimiter=","
$Domain="YOURDOMAIN.COM"
$UniqueId="EmployeeID"
$OUProperty="Office"
$KeepDisabledForDays=7

Validate-OU -SyncFieldMap $SyncFieldMap -CSVFilePath $CsvFilePath `
-Delimiter $Delimiter -Domain $Domain -OUProperty $OUProperty

$UserSyncData=Get-UserSyncData -SyncFieldMap $SyncFieldMap -UniqueID $UniqueId `
    -CSVFilePath $CsvFilePath -Delimiter $Delimiter -Domain $Domain -OUProperty $OUProperty

Create-NewUsers -UserSyncData $UserSyncData -Verbose

Sync-ExistingUsers -UserSyncData $UserSyncData -SyncFieldMap $SyncFieldMap -Verbose

Remove-Users -UserSyncData $UserSyncData -KeepDisabledForDays $KeepDisabledForDays -Verbose

