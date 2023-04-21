#Requires -RunAsAdministrator
#Requires -Version 3.0
<#PSScriptInfo
.VERSION 0.0.1
.AUTHOR Quentin SCHWEITZER
.SYNOPSIS
Create AD OU, security groups and random users.
.DESCRIPTION
With a JSON response file (required), this tool will create automatically OU and add users in them with defined values in JSON. Users could be automatically added to specified groups.
This tool also can create some defined security groups in specified OUs.
.RELEASENOTES
- First release.
#>

#region FONCTIONS

Function Write-Log {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        [Parameter(Mandatory = $false, Position = 1)]
        [string]$Prefix,
        [string]$Suffix,
        [ValidateSet("info", "error", "warning", "debug", IgnoreCase = $true)]
        [string]$Type
    )
    $ColorHT = @{
        info    = @{BackgroundColor = "DarkCyan"; ForegroundColor = "White"; Text = "INFO" }
        error   = @{BackgroundColor = "Red"; ForegroundColor = "White"; Text = "ERROR" }
        warning = @{BackgroundColor = "Yellow"; ForegroundColor = "DarkBlue"; Text = "WARNING" }
        debug   = @{BackgroundColor = "White"; ForegroundColor = "Black"; Text = "DEBUG" }
        success   = @{BackgroundColor = "Green"; ForegroundColor = "Black"; Text = "SUCCESS" }
    }
    Function ThisHHmmss() {
        (Get-Date).ToString("HH:mm:ss")
    }
    switch ($Type) {
        { $ColorHT."$($Type)" } {
            $ChoosenType = $ColorHT."$($Type)"
        }
    }
    $Log = "$(ThisHHmmss) ||$(if($ChoosenType){"$($ChoosenType.Text)||"}) $(if($Prefix){"$($Prefix) | "})$($Message)$(if($Suffix){" | $($Suffix)"})"
    if ($Type) {
        Write-Host $Log -BackgroundColor $ChoosenType.BackgroundColor -ForegroundColor $ChoosenType.ForegroundColor
    }
    else {
        Write-Host $Log
    }
    $Script:Logs += [pscustomobject]$Log
    $Script:Logs | out-file -Encoding UTF8 -FilePath $LogFile -Append
}

function Invoke-ScriptIntro {
    # Create multiple ASCII art title banners.
    $Spacing = "`t"
    $InvokeScriptIntroAscii  = @()
    $InvokeScriptIntroAscii += $Spacing + '    ___          __   _               ____   _                    __                     '
    $InvokeScriptIntroAscii += $Spacing + '   /   |  _____ / /_ (_)_   __ ___   / __ \ (_)_____ ___   _____ / /_ ____   _____ __  __'
    $InvokeScriptIntroAscii += $Spacing + '  / /| | / ___// __// /| | / // _ \ / / / // // ___// _ \ / ___// __// __ \ / ___// / / /'
    $InvokeScriptIntroAscii += $Spacing + ' / ___ |/ /__ / /_ / / | |/ //  __// /_/ // // /   /  __// /__ / /_ / /_/ // /   / /_/ / '
    $InvokeScriptIntroAscii += $Spacing + '/_/ _|_|\___/ \__//_/  |___/ \___//_____//_//_/   _\___/ \___/ \__/ \____//_/    \__, /  '
    $InvokeScriptIntroAscii += $Spacing + '   / __ \ ____ _ ____   ____/ /____   ____ ___   (_)____  ___   _____           /____/   '
    $InvokeScriptIntroAscii += $Spacing + '  / /_/ // __ `// __ \ / __  // __ \ / __ `__ \ / //_  / / _ \ / ___/                    '
    $InvokeScriptIntroAscii += $Spacing + ' / _, _// /_/ // / / // /_/ // /_/ // / / / / // /  / /_/  __// /                        '
    $InvokeScriptIntroAscii += $Spacing + '/_/ |_| \__,_//_/ /_/ \__,_/ \____//_/ /_/ /_//_/  /___/\___//_/                         '
    $InvokeScriptIntroAscii += $Spacing + '                                                                                         '

    $FirstApprochAscii  = @()
    $FirstApprochAscii += '> Randomize'
    $FirstApprochAscii += '> Your AD users'
    $FirstApprochAscii += '> and'
    $FirstApprochAscii += '> Make'
    $FirstApprochAscii += '> Your own architecture'

    # Display primary ASCII art title banner.
    $RandomColor = (Get-Random -Input @('Green','Cyan','Yellow'))
    ForEach($Line in $InvokeScriptIntroAscii)
    {
        Start-Sleep -Milliseconds 100
        Write-Host $Line -ForegroundColor $RandomColor
        Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 300)
    }

    Start-Sleep -Milliseconds 650
    ForEach($Line in $FirstApprochAscii) {
        Start-Sleep -Milliseconds (Get-Random -Minimum 0 -Maximum 300)
        Write-Host $Line -ForegroundColor $RandomColor
    }
    Start-Sleep -Milliseconds 100

    # Output tool banner after all ASCII art.
    Write-Host ""
    Start-Sleep -Milliseconds 100
    Write-Host "`tTool    :: ActiveDirectory Randomizer" -ForegroundColor Magenta
    Start-Sleep -Milliseconds 100
    Write-Host "`tAuthor  :: Quentin SCHWEITZER" -ForegroundColor Magenta
    Start-Sleep -Milliseconds 100
    Write-Host "`tTwitter :: @MrTr3z" -ForegroundColor Magenta
    Start-Sleep -Milliseconds 100
    Write-Host "`tGithub  :: https://github.com/qschweitzer" -ForegroundColor Magenta
    Start-Sleep -Milliseconds 100
    Write-Host "`tVersion :: 0.0.1" -ForegroundColor Magenta
    Start-Sleep -Milliseconds 100
    Write-Host "`tLicense :: MIT License" -ForegroundColor Magenta
    Start-Sleep -Milliseconds 100

}

Function Invoke-Menu {
	# This part is inspired from Daniel Bohannon's script: Invoke-Obfuscat*on
    $LineSpacing = '[*] '
    $RandomColor = (Get-Random -Input @('Green','Cyan','Yellow'))

    # Main Menu.
    $MenuGenerationName = @()
    $MenuGenerationName += "                 __,                        ,__"
    $MenuGenerationName += "              __/==+\  TYPE A GENERATION  /+==\__"
    $MenuGenerationName += '                "  "`  ===== NAME  =====  '+'"  '
    $MenuGenerationName += '              ==== DEFAULT IS ADGenerationFR ===='
    $MenuGenerationName | ForEach-Object { Write-Host "`t$($_)" -ForegroundColor $RandomColor}

    [string]$Script:GenerationName = Read-Host -Prompt "GenerationName"
    if($Script:GenerationName -eq ""){$Script:GenerationName = "ADGenerationFR"}
	
	Write-Host "INTERNET CONNECTION REQUIRED TO RETRIEVE GENERATED USERS" -backgroundcolor yellow -foregroundcolor black
	Write-Host "START THIS TOOL FROM A SERVER WITH ACTIVE DIRECTORY POWERSHELL MODULES INSTALLED" -backgroundcolor yellow -foregroundcolor black

    $MenuLanguages =   @()
    $MenuLanguages+= "Choose country to generate users"
    $MenuLanguages+= "Available:"
    $Languages = @('FR (default)','GB','AU','CA','CH','DE','DK','ES','FI','IE','IR','NL','NZ','TR','US')

    $MenuLanguages | ForEach-Object { Write-Host "`t$($_)" -ForegroundColor $RandomColor}
    $Languages | ForEach-Object { Write-Host "`t$($LineSpacing)$($_)" -ForegroundColor Yellow}
    $Script:SelectedCountry = Read-Host -Prompt "Language to use"

    if($Script:SelectedCountry -eq ""){$Script:SelectedCountry="FR"}

    $JSONFound = Get-ChildItem $PSScriptRoot -Filter *.json | select Name

    Write-Host -ForegroundColor Magenta "`tJSON found, select good JSON to use"
    $i = 1
    $JSONFound | ForEach-Object {
        Write-Host ("`t"+$i) -ForegroundColor Yellow -NoNewline
        Write-Host ("`t"+$_.name) -ForegroundColor Green
        $i++
    }

    $SelectedJSON = Read-Host -Prompt "Select your JSON parameter: "
    $Script:SelectedJSON = $JSONFound[$SelectedJSON-1].Name
}

Function Format-OUName {
param($OUName)

    $SplittedName = $OUName.split("\")
    [array]::Reverse($SplittedName)
    $EndName = "DC=$($env:USERDNSDOMAIN.split(".")[0]),DC=$($env:USERDNSDOMAIN.split(".")[-1])"
    $NewName = ""
    $NewName = "OU="+ ($SplittedName -join ",OU=") + "," + $EndName

return $NewName
}

Function Create-ADUser {
param($UsersArray,$OU,$Group)
    Write-Log -Type info ([string]$UsersArray.count + " Users on group " + $Group)
    $UsersArray | ForEach-Object {
        [string]$DisplayName = ($_.Name.first + " " + $_.Name.last)
        Write-Log -Type debug -Prefix "USER CREATION" -Message "$($DisplayName)"
        [string]$SamAccountName = (($_.Name.first).substring(0,1) +"."+ $_.Name.last)
        try{
            $i = 1
            While(Get-ADUser -Identity $SamAccountName){
                $SamAccountName = (($_.Name.first).substring(0,$i)+"."+ $_.Name.last)
                $i++
            }
        }catch{}
        [string]$GivenName = $_.Name.first
        [string]$SurName = $_.Name.last
        [string]$UserPrincipalName = ($SamAccountName + "@" + $env:USERDNSDOMAIN)
        [string]$Email = $_.email
        $PasswordPlainText = ("0!Aa"+$_.login.password)
        $Password = ($PasswordPlainText | ConvertTo-SecureString -AsPlainText -Force)
        [string]$City = $_.location.city
        [string]$Address = ([string]($_.location.street.number)+" "+($_.location.street.name))
        [string]$PostalCode = $_.location.postcode
        [string]$State = $_.location.state
        [string]$OfficePhone = $_.phone
        [string]$MobilePhone = $_.cell
		$_.location.psobject.properties.remove("timezone")
		$_.location.psobject.properties.remove("coordinates")
		$_.login.psobject.properties.remove("uuid")
		$_.login.psobject.properties.remove("username")
		$_.login.psobject.properties.remove("salt")
		$_.login.psobject.properties.remove("md5")
		$_.login.psobject.properties.remove("sha1")
		$_.login.psobject.properties.remove("sha256")
		$_.name.psobject.properties.remove("title")
		$_.login | Add-Member -MemberType NoteProperty -Name "SamAccountName" -Value $SamAccountName

        if(!($DisplayName -in $Script:ADUsers.DisplayName)){
            Write-Log -Type info -Prefix "USER CREATION" -Message "Creating ADUser $($DisplayName)"
            Write-Log -Type info -Prefix "USER CREATION" -Message "SamAccountName: $($SamAccountName)"
            New-ADUser -Path $OU -DisplayName $DisplayName -AccountPassword $Password -SamAccountName $SamAccountName -UserPrincipalName $UserPrincipalName -GivenName $GivenName -Surname $SurName -Name $DisplayName -Enabled $true -City $City -State $State -StreetAddress $Address -EmailAddress $Email -OfficePhone $OfficePhone -Office $Office -PostalCode $PostalCode -MobilePhone $MobilePhone -ErrorAction SilentlyContinue -ErrorVariable erroruser
            # IF ERROR
            if($usererror){
                Write-Log -Type error -Prefix "USER CREATION" -Message "Error about user $($DisplayName). Error Message: $($erroruser)"
                Remove-Variable -Name erroruser -Force
            }else{
                Write-Log -Type info -Prefix "USER CREATION" -Message "User $($DisplayName) created."
                # ADD USER TO GROUP
                Write-Log -Type debug -Prefix "USER IN GROUP" -Message "Adding user $($DisplayName) on group $($Group)"
                
                # CHECK IF GROUPS EXISTS AND CREATES IF NOT
                Write-Log -Type info -Prefix "USER IN GROUP" -Message "Control if group $($Group) exists"
                $Group | ForEach-Object {
                    $LineGroup = $_
                    Create-ADGroup -GroupName $LineGroup -OU $OU -FromUserCreation

                    Add-ADGroupMember -Identity $LineGroup -Members $SamAccountName -Confirm:$false -ErrorAction SilentlyContinue -ErrorVariable erroraddusertogroup
                    # IF ERROR
                    if($erroraddusertogroup){
                        Write-Log -Type error -Prefix "USER IN GROUP" -Message "Error about adding user $($DisplayName) to group $($LineGroup). Error Message: $($erroraddusertogroup)"
                        Remove-Variable -Name erroraddusertogroup -Force
                    }else{
                        Write-Log -Type info -Prefix "USER IN GROUP" -Message "User $($DisplayName) added to group $($LineGroup)."
                    }
                }
                
            }
        }
        else{
            Write-Log -Type info -Prefix "USER CREATION" -Message "User $($DisplayName) already exists"
        }
    }
	return $UsersArray
}

Function Create-ADOU {
param($OU)
    $ParentOU = $OU.split(",",2)[1]
    $OUName = ($OU.replace("OU=","").split(",")[0])

    # IF ONE OU DOESNT EXISTS, CREATE IT
    try{
        Get-ADOrganizationalUnit -filter * -SearchBase $OU | Out-Null
    }
    catch{
        try{
            Get-ADOrganizationalUnit $ParentOU | Out-Null
            New-ADOrganizationalUnit -path $ParentOU -name $OUName -Confirm:$false
            Write-Log -Type info -Prefix "OU CREATION" -Message  "OU: $($OU) has been created"
        }
        catch{
                $ParentOUMore = $ParentOU.split(",",2)[1]
                $ParentOUName = (($ParentOU.split(",",2)[0]).replace("OU=","").split(",")[0])
            Do{
                
                Write-Log -Type warning -Prefix "OU CREATION" -Message  "Creating parent OU: $($ParentOUName) on $($ParentOUMore)"
                New-ADOrganizationalUnit -path $ParentOUMore -name $ParentOUName -Confirm:$false
                if($ParentOUMore.split(",").count -eq 3){
                    break
                }
                $ParentOUMore = $ParentOUMore.split(",",2)[1]
                $ParentOUName = (($ParentOU.split(",",2)[0]).replace("OU=","").split(",")[0])
            }until(Get-ADOrganizationalUnit $ParentOUMore -ErrorAction SilentlyContinue | out-null)
            New-ADOrganizationalUnit -path $ParentOU -name $OUName -Confirm:$false
            Write-Log -Type info -Prefix "OU CREATION" -Message  "OU: $($OU) has been created"
        }
    }
}

Function Create-ADGroup {
param($GroupName,$OU,[switch]$FromUserCreation)
    try{
        Get-ADGroup -Identity $GroupName | Out-Null
        if(!$FromUserCreation){
            Write-Log -Type info -Prefix "GROUP CREATION" -Message "Group $($GroupName) already exists !"
        }
    }
    catch{
        # CREATING GROUPS ON OU
        if($null -ne $GroupName){
            Write-Log -Type debug -Prefix "GROUP CREATION" -Message "Creating Group $($GroupName)"
            if($FromUserCreation){
                Write-Log -Type warning -Prefix "GROUP CREATION" -Message "Creating Group $($GroupName) will be created in same OU as user because not specified in GROUPS array into the source JSON !"
            }
            Create-ADOU -OU $OU
            New-ADGroup -Name $GroupName -DisplayName $GroupName -Path $OU -Groupcategory Security -GroupScope Global -SamAccountName $GroupName -Confirm:$false -ErrorVariable errorgroup -ErrorAction SilentlyContinue | Out-Null
                
            # IF ERROR
            if($errorgroup){
                Write-Log -Type error -Prefix "GROUP CREATION" -Prefix "GROUP CREATION" -Message "Error about group $($GroupName). Error Message: $($errorgroup)"
                Remove-Variable -Name errorgroup -Force
            }else{
                Write-Log -Type info -Prefix "GROUP CREATION" -Message "Group $($GroupName) created."
            }
        }
        else{
            Write-Log -Type error -Prefix "GROUP CREATION" -Message "Group name is empty !"
        }
    }
}

#endregion FONCTIONS

#region LOGS
$Script:Logs = @()
$LogFolder = "$($PSScriptRoot)\LOGS"
if (!(Test-Path $LogFolder)) { mkdir $LogFolder }
$LogFile = "$($LogFolder)\Logs_$(get-date -Format "dd.MM.yyyy_HH.mm.ss").log"
#endregion LOGS

#region SCRIPT BLOCK

Invoke-ScriptIntro
Invoke-Menu
$DefaultRepo = "C:\ADGeneration"
$FullPathToExport = $DefaultRepo+"\"+$Script:GenerationName+".json"
$JSONConfigFile = $PSScriptRoot+"\"+$Script:SelectedJSON
$JSONConfig = Get-Content -Path $JSONConfigFile | ConvertFrom-Json -ErrorAction SilentlyContinue -ErrorVariable badjson
# IF ERROR JSON
if($badjson){
    Write-Log -Type error -Prefix "JSON IMPORT" -Message "Error about JSON import. Check your JSON syntax. Error Message: $($badjson)"
    Write-Log -Type warning -Prefix "EXIT" -Message "Fix your JSON issue and restart script."
    Pause
    Exit
}

# COUNT USERS ON EACH OU FROM JSON
$TotalUsers = ($JSONConfig.OU.NbUsers | Measure-Object -Sum).sum
$OUtoCreate = $JSONConfig.OU
$GroupsToCreate = $JSONConfig.GROUPS
$Script:ADUsers = Get-ADUser -Filter * -Properties SamAccountName,DisplayName

# IF EXPORT FOLDER DOESNT EXIST, CREATE
if(!(Test-Path $DefaultRepo)){
    mkdir $DefaultRepo
}
# IF EXPORTED JSON ALREADY EXISTS, WARNING AND SLEEP UNTIL CONFIRM
if(Test-Path $FullPathToExport){
    Write-Log -Type warning -Prefix "EXPORT CONTROL" -Message "Fichier $($FullPathToExport) d�j�existant. Il sera supprim� si vous continuez."
    pause
}

# GETTING RANDOM USERS FROM Randomuser.me's API
$APIResultsJSON = (Invoke-RestMethod -Method GET -Uri "https://randomuser.me/api/?seed=$($Script:GenerationName)&exc=gender,registered,dob,id,picture&password=upper,number,10&results=$($TotalUsers)&nat=$($Script:SelectedCountry)" | ConvertTo-JSON -Depth 5)

$UsersGenerated = ($APIResultsJSON | ConvertFrom-Json).Results
$LastUserInList = 0
$CreatedUsersInAD = @()

# OU PATH REWRITING
$JSONConfig.OU | ForEach-Object { $_.OUName = (Format-OUName -OUName ($_.OUName)) }
$JSONConfig.GROUPS | ForEach-Object { $_.OU = (Format-OUName -OUName ($_.OU)) }

# CREATING GROUPS ON ACTIVE DIRECTORY
$JSONConfig.GROUPS | ForEach-Object {
    $OU = $_.OU
    $GROUPS = $_.GROUPS
    
    # CHECK IF OU EXISTS AND CREATE IF NOT
    Create-ADOU -OU $OU
    
    Write-Log -Type debug -Prefix "GROUP CREATION" -Message "Checking existing groups on OU $($OU)"
    
    # CREATING GROUPS ON OU
    $GROUPS | ForEach-Object {
        $GroupName = $_
        Create-ADGroup -GroupName $GroupName -OU $OU
    }
}

# CREATING OU AND USERS IN ACTIVE DIRECTORY
$JSONConfig.OU | ForEach-Object {
    $OU = $_.OUName
    $NbUsers = $_.NbUsers
    $Group = $_.UsersDefaultGroups

    # CHECK IF EXISTING OU AND CREATE IF NOT
    Create-ADOU -OU $OU
    
    # CREATING USERS IN OU + ADDING USERS TO SPECIFIED GROUPS
    if($null -ne $_.NbUsers){
        if($LastUserInList -eq 0){
            $UserList = $UsersGenerated | select -First ($NbUsers)
        }
        else{
            $UserList = $UsersGenerated | select -First ($LastUserInList+$NbUsers) | select -Last ($NbUsers)
        }
        $CreatedUsersInAD += Create-ADUser -UsersArray $UserList -OU $OU -Group $Group
        $LastUserInList = ($LastUserInList + $NbUsers)
    }
}

# EXPORTING RESULTS ON JSON TO FUTURE USE
$CreatedUsersInAD | convertto-json | Out-File -FilePath $FullPathToExport -Encoding UTF8 -Force

#endregion SCRIPT BLOCK
