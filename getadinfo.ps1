<#
.SYNOPSIS
    Uses Get-ADUser to display AD user attributes in a 'pretty' way for the command line.
.DESCRIPTION
    Combines Get-ADUser cmdlet with a configuration file (JSON) to parse the following:
     - domain controllers
     - user attributes/properties,
     - aliases
     - specific group formatting
     - modifiers (ex. copying attribute to clipboard).
    'config.json' must be placed in the same working dir as the script to function.
.PARAMETER Path
    The path to the .
.EXAMPLE
    .\getadinfo.ps1 USER001 c
    .\getadinfo.ps1 USER002
.LINK
    https://github.com/choehn86/getadinfo
#>

[cmdletbinding()]
param (
	# samAccountName to query against AD (required)
    [Parameter(Mandatory=$true)]
    [string]$userID,
    # generic modifier - currently used to copy a specified attribute from the config file to the clipboard (optional)
    [char] $modifer
)

if ($PSBoundParameters['Debug']) 
{
    $DebugPreference = 'Continue'
}

# Load and parse the JSON configuration file
try 
{
	$config = Get-Content -Path "$PSScriptRoot\config.json" -Raw -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue | 
        ConvertFrom-Json -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
} 
catch 
{
    Write-Error -Message "The Base configuration file is missing!" -ErrorAction Stop
}

# Check configuration file; if valid then assign values to global vars
if (!($config)) 
{
	Write-Error -Message "No data found in config file!" -ErrorAction Stop
}
else
{
    if( ($global:DCs = $config.getadinfo.domaincontrollers).length -eq 0 ) { Write-Debug "No DCs parsed from file, resorting to default logon server" }     
    if( ($global:props = $config.getadinfo.properties.props).length -eq 0 ) { Write-Debug "No properties parsed, will return ALL properties on match" }
    if( ($global:aliases = $config.getadinfo.properties.aliases).length -eq 0 ) { Write-Debug "No aliases parsed from file" }
    if( ($global:groupformatting = $config.getadinfo.groupformatting).length -eq 0 ) { Write-Debug "No group formating parsed from file" }
    if( ($global:modifier = $config.getadinfo.modifier).length -eq 0 ) { Write-Debug "No modifiers parsed from file" }
}

function Check-Command($cmdname) # checks if cmdlet is loaded/installed
{
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

if(Check-Command('Get-ADUser'))
{
    try
    {
        Write-Debug "Found Get-ADUser cmdlet!"
        $c = 0
        $user = $null
        $groups = $null
        $defaultDC = $($env:LOGONSERVER.Replace('\','')  + "." + $env:USERDNSDOMAIN)
        $defaultGroupColor = 'cyan'

        while($c -le [int]$global:DCs.Count)
        {
            try
            {
                if($c -lt [int]$global:DCs.Count)
                {
                    $user = Get-ADUser $userID -Server $global:DCs[$c] -Properties * | Select -Property $global:props
                    break;
                }
                else
                {
                    $user = Get-ADUser $userID -Properties * | Select -Property $global:props
                    break;
                }
            }
            catch [Microsoft.ActiveDirectory.Management.ADServerDownException]
            {
                switch (([int]$global:DCs.Count - $c))
                {
                    0 { $errorstr = "Unable to reach $defaultDC" }
                    1 { $errorstr = "Unable to reach $($global:DCs[$c]), using $defaultDC" }
                    default {  $errorstr = "Unable to reach $($global:DCs[$c]),trying next DC in config file..." }
                }
                Write-Debug $errorstr
                $c++
            }
        }

        if($user)
        {
            $user | Add-Member -MemberType NoteProperty -Name objectGUID -Value (($user.ObjectGUID.ToByteArray() | foreach { $_.ToString("X2") }) -join '' ) -Force
            if($global:aliases) { $global:aliases | Foreach-Object { Add-Member -InputObject $user -MemberType AliasProperty -Name $_.name -Value $_.prop -Force -ErrorAction SilentlyContinue } }
     
            # handle any supplied modifiers
            foreach($gmod in $global:modifier)
            {    
                switch($modifer)
                {
                    'c' # copy attribute to clipboard
                        {
                            if($gmod.action -eq 'copy')
                            {
                                $user.($gmod.name).Replace([string]$gmod.omit,"") | Set-Clipboard
                                Write-Debug "copied $($gmod.name) to clipboard" 
                            }
                        }      
                }
            }

            $user | Select -Property * -ExcludeProperty $($global:aliases.prop + ("memberOf"))

            if($user.memberOf.length -gt 0)
            {
                [int]$counter = 1
                $groups = $user.memberOf.replace("CN=", "") | Sort-Object { ($_ -match "$($global:groupformatting.filter -join '|')") } -Descending
            
                "------------------  Member Of ------------------"           
                foreach($group in $groups)
                {
                    $groupColor = $defaultGroupColor
                    foreach($fmt in $global:groupformatting)
                    {
                        if( $group -match $fmt.filter ) { $groupColor = $fmt.color }
                    }
                    Write-Host ('' + $counter + ' >> ' + $group) -foregroundColor $groupColor
                    $counter++  
                }
                "------------------------------------------------"
            }
            else { "User is not a member of any groups!" }
        } 
        else { "No data found" }
    }
    catch { $_  }
}
else { 'Get-ADUser cmdlet not found!' }
