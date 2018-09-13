<#
.SYNOPSIS
    Uses Get-ADUser (or Directory Searcher) to display AD user attributes in a 'pretty' way for the command line.
.DESCRIPTION
    Combines AD query with a configuration file (JSON) to parse the following:
     - domain controllers
     - user attributes/properties
     - aliases
     - specific group formatting
     - modifiers (ex. copying attribute to clipboard)
    'config.json' must be placed in the same working dir as the script to function.
.PARAMETER Path
    The path to the .
.EXAMPLE
    .\getadinfo.ps1 USER000 -ForceDS
    .\getadinfo.ps1 USER001 -Copy
    .\getadinfo.ps1 USER002 -Copy mail
    .\getadinfo.ps1 USER003
.LINK
    https://github.com/choehn86/getadinfo
#>

[cmdletbinding()]
param (
	# samAccountName to query against AD (required)
    [Parameter(Position = 0, Mandatory=$true)]
    [string]$userID,
    
    # copies specificed attribute to clipboard (default attribute is built into config file) 
    [Parameter(Position = 1, ParameterSetName='copyattr')]
    [switch]$copy,
    
    # if provided overrides the default attribute from the config file for the copy function
    [Parameter(Position = 2, ParameterSetName='copyattr')]
    [string]$copyAttr,
    
    # switch to force script to use DirectorySearcher instead of Get-ADUser
    [Parameter(Position = 3)]
    [switch]$ForceDS
)

if($PSBoundParameters['Debug']) { $DebugPreference = 'Continue' }

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
if (!($config)) { Write-Error -Message "No data found in config file!" -ErrorAction Stop }
else
{
    if( ($global:DCs = $config.getadinfo.domaincontrollers).length -eq 0 ) { Write-Debug "No DCs parsed from file, resorting to default logon server" }     
    if( ($global:props = $config.getadinfo.properties.props).length -eq 0 ) { Write-Debug "No properties parsed, will return ALL properties on match" }
    if( ($global:aliases = $config.getadinfo.properties.aliases).length -eq 0 ) { Write-Debug "No aliases parsed from file" }
    if( ($global:groupformatting = $config.getadinfo.groupformatting).length -eq 0 ) { Write-Debug "No group formating parsed from file" }
    if( ($global:modifier = $config.getadinfo.modifier).length -eq 0 ) { Write-Debug "No modifiers parsed from file" }
}

if($copy)     { Write-Debug 'Copy switch specified!' }
if($copyAttr) { Write-Debug ($copyAttr + ' to be copied!') }
if($ForceDS)  { Write-Debug 'Forcing DirectorySearcher!' }

function Check-Command($cmdname) # checks if cmdlet is loaded/installed
{
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

$c = 0
$user = $null
$groups = $null
$defaultDC = $($env:LOGONSERVER.Replace('\','')  + "." + $env:USERDNSDOMAIN)
$defaultGroupColor = 'cyan'

if($(Check-Command('Get-ADUser')) -and !($ForceDS))
{
        Write-Debug "Found Get-ADUser cmdlet!"
        $DC = $null

        while($c -le [int]$global:DCs.Count)
        {
            switch($c)
            {
                $global:DCs.Count { $DC = $defaultDC }
                default           { $DC = $global:DCs[$c] }
            }

            try { $user = Get-ADUser $userID -Server $DC -Properties * | Select -Property $global:props; break }

            catch [Microsoft.ActiveDirectory.Management.ADServerDownException]
            {
                switch (([int]$global:DCs.Count - $c))
                {
                    0       { $errorstr = "Unable to reach $defaultDC" }
                    1       { $errorstr = "Unable to reach $($global:DCs[$c]), using $defaultDC" }
                    default { $errorstr = "Unable to reach $($global:DCs[$c]),trying next DC in config file..." }
                }
                Write-Debug $errorstr
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]
            {
                "User $userID not found"
                break
            }
            $c++
        }
        # convert objectguid
        if($user) { $user | Add-Member -MemberType NoteProperty -Name objectGUID -Value (($user.ObjectGUID.ToByteArray() | foreach { $_.ToString("X2") }) -join '' ) -Force  }  
}
else 
{ 
    if(!$ForceDS) { Write-Debug "Get-ADUser not found, using DirectorySeacher!" }

    $colResults = $null
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.PageSize = 1000
    $objSearcher.Filter = "(&(objectCategory=User)(samAccountName=$userID))"
    $objSearcher.SearchScope = "Subtree"

    while($c -le [int]$global:DCs.Count)
    {
        switch($c)
        {
            $global:DCs.Count { $objSearcher.SearchRoot = [adsi] "LDAP://$defaultDC" }
            default           { $objSearcher.SearchRoot = [adsi] "LDAP://$($global:DCs[$c])" }
        }

        try { $colResults = $objSearcher.FindOne(); break }
        catch [System.Runtime.InteropServices.COMException]
        {
           if($_.Exception.Message.Trim() -eq "The server is not operational.")
           {
               switch (([int]$global:DCs.Count - $c))
               {
                   0       { $errorstr = "Unable to reach $defaultDC" }
                   1       { $errorstr = "Unable to reach $($global:DCs[$c]), using $defaultDC" }
                   default { $errorstr = "Unable to reach $($global:DCs[$c]),trying next DC in config file..." }
               }
               Write-Debug $errorstr
           }
        }
        $c++
    }

    if($colResults.Count -gt 0)
    {
        $user = New-Object PSObject

        foreach($p in $props)
        {
            # check if attribute exists and assign to val (switch is used for further processing based on properties returned)
            $val = if($colResults.Properties[$p].Count -gt 0) { $colResults.Properties[$p].GetEnumerator() | % { $_ } } else { '' }

            switch($p)
            {
                # check UAC to see if account is Enabled or Disabled
                'Enabled'      { $val = [string]!( (($val) -band 2) -eq 2) }
                # convert objectguid
                'objectguid'   { $val = ($val | % { $_.ToString("X2") }) -join '' } 
                'memberOf'     { $val = $val | % { $_ } }
            }
            $user | Add-Member -MemberType NoteProperty -Name $p -Value $val
        }
    }
    else { "User $userID not found" }
}

# check for valid user and process

if($user)
{
    # parse and add aliases to user
    if($global:aliases) { $global:aliases | % { Add-Member -InputObject $user -MemberType AliasProperty -Name $_.name -Value $_.prop -Force -ErrorAction SilentlyContinue } }
     
    # handle any supplied modifiers
    foreach($gmod in $global:modifier)
    {    
        # copy function
        if(($gmod.action -eq 'copy') -and ($copy.IsPresent))
        {
            # copy specified attribute to clipboard
            if($copyAttr.Length -gt 0) { $user.$copyAttr | Set-Clipboard; Write-Debug "copied $copyAttr to clipboard" }
            # copy default attribute from config file
            else { $user.($gmod.name).Replace([string]$gmod.omit,"") | Set-Clipboard; Write-Debug "copied $($gmod.name) to clipboard" }
            break
        }
    }

    $user | Select -Property * -ExcludeProperty $($global:aliases.prop + ("memberOf"))

    if($user.memberOf.length -gt 0)
    {
        $counter = 1
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
    
    "Completed on: $(Get-Date -format g)"
}
