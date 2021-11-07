function Validate-Groups{
    [CmdletBinding()]
    Param(
       [Parameter(Mandatory)]
       [xml]$XML,
       [Parameter(Mandatory)]
       [string]$Server,
       [Parameter()]
       [bool]$Create=$false
    )

    try{
        $XMLGroups=$XML.data.group

        $Result=[System.Collections.ArrayList]@()

        foreach($group in $XMLGroups){
            $GroupName=$group.name
            $ADGroup=Get-ADGroup -filter {name -like $GroupName} -Server $Server
            $ResultEntry=New-Object -TypeName PSObject
            Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "GroupName" -Value $GroupName
            if($ADGroup){
                Write-Verbose "Group Exists"
                Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Exists" -Value $true
                Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Notes" -Value "Group existed" 
            }else{
                Write-Verbose "Group $GroupName does not Exist"
                
                if($Create){
                    Write-Verbose "Creating group $GroupName"
                    $GroupData=@{
                        Name=$GroupName
                        SamAccountName=$GroupName
                        Description="Group created by script"
                        GroupCategory="Security"
                        GroupScope="Global"
                        Server=$Server
                    }

                    New-ADGroup @GroupData

                    $ADgroup=Get-ADGroup -filter {name -like $GroupName} -Server $Server

                    if($ADGroup){
                        Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Exists" -Value $true
                        Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Notes" -Value "Group was created by script"
                    }else{
                        Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Exists" -Value $false
                        Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Notes" -Value "Group was not created, error, please check Active Directory"
                    }


                }else{
                    Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Exists" -Value $false
                    Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Notes" -Value "Create command not executed"
                }
            }
            [void]$Result.Add($ResultEntry)
        }
        return $Result
    }catch{
        Write-Error -Message $_.Exception.Message
    }
}

function Manage-Groups{
    [CmdletBinding()]
    Param(
       [Parameter(Mandatory)]
       [xml]$XML,
       [Parameter(Mandatory)]
       [string]$Server,
       [Parameter()]
       [bool]$Create=$false
    )

    if($Create){
        $Groups=Validate-Groups -XML $XMLData -Server $Server -Create $true
    }else{
        $Groups=Validate-Groups -XML $XMLData -Server $Server
    }
    

    $Result=[System.Collections.ArrayList]@()

    $XMLGroups=$XML.data.group

    foreach($Group in $XMLGroups){
        $ResultEntry=New-Object -TypeName PSObject
        Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "ValidateResult" -Value $($Groups | where groupname -eq $group.name)
    if($Group.name -in $($Groups | Where-Object Exists -EQ $true).groupname){
        $Adds=$null
        $Removes=$null
        $CompareResults=$null
        $UsersBelong=$null
        $CurrentUsers=$null

        Write-Verbose "$($Group.name) exist"

        $TitlesInGroup=$Group.titles.title
        $UsersBelong=Get-ADUser -Filter * -Server $Server -Properties * | Where-Object title -In $TitlesInGroup
        $CurrentUsers=Get-ADGroupMember -Identity $Group.name -Server $Server

        if($UsersBelong -and $CurrentUsers){
            $CompareResults=Compare-Object -ReferenceObject $UsersBelong -DifferenceObject $CurrentUsers -Property SamAccountName
            $Adds=$CompareResults | Where-Object SideIndicator -eq "<="
            $Removes=$CompareResults | Where-Object SideIndicator -eq "=>"
        }elseif($UsersBelong){
            Write-Verbose "Add all users to group"
            $Adds=$UsersBelong
        }elseif($CurrentUsers){
            Write-Verbose "Remove all users from the group"
            $Removes=$CurrentUsers
        }else{
            Write-Verbose "Do nothing, no one in group, no one belongs to group"
        }

        if($Adds){
            Write-Verbose "Performing adds..."
            Add-ADGroupMember -Identity $Group.name -Members $Adds.samaccountname -Server $Server
            Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Adds" -Value $adds.samaccountname
        }else{
            Write-Verbose "No users to add..."
            Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Adds" -Value $null
        }

        if($Removes){
            Write-Verbose "Performing removes..."
            Remove-ADGroupMember -Identity $Group.name -Members $Removes.samaccountname -Server $Server -Confirm:$false
            Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Removes" -Value $Removes.samaccountname
        }else{
            Write-Verbose "No users to remove..."
            Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Removes" -Value $null
        }
    }else{
        Write-Verbose "$($Group.name) does not exist"
        Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Adds" -Value $null
        Add-Member -InputObject $ResultEntry -MemberType NoteProperty -Name "Removes" -Value $null
    }

        $Result+=$ResultEntry
    }

    return $Result
}


$XMLFilePath="C:\scripts\AutomateAD\Groups.xml"

[xml]$XMLData=Get-Content -Path $XMLFilePath
$Server="jacked.ca"

$Results=Manage-Groups -XML $XMLData -Server $Server -Create $true

foreach($Result in $Results){
    Write-Output "$($Result.ValidateResult.GroupName) : Exists : $($Result.ValidateResult.Exists) Notes : $($Result.ValidateResult.Notes)"
    if($Result.Adds){
        foreach($Add in $Result.Adds){
            Write-Output "Added $($Add) to $($Result.ValidateResult.GroupName)"
        }
    }
    if($Result.Removes){
        foreach($Remove in $Result.Removes){
            Write-Output "Removed $($Remove) from $($Result.ValidateResult.GroupName)"
        }
    }
}
