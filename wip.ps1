[cmdletbinding()]
param (
	[string]$userID,
    [char] $modifer
)

if ($PSBoundParameters['Debug']) 
{
    $DebugPreference = 'Continue'
}

# Load and parse the JSON configuration file
try 
{
	$config = Get-Content -Path .\config.json -Raw -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue | ConvertFrom-Json -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue
} 
catch 
{
    Write-Error -Message "The Base configuration file is missing!" -ErrorAction Stop
}

# Check configuration file; if valid then assign values to global vars
if (!($config)) 
{
	Write-Error -Message "The Base configuration file is missing!" -ErrorAction Stop
}
else
{
    $global:DCs = ($config.getadinfo.domaincontrollers)
    $global:props = ($config.getadinfo.properties.props)
    $global:aliases = ($config.getadinfo.properties.aliases)
    $global:groupformatting = ($config.getadinfo.groupformatting)
    $global:copyattribute = ($config.getadinfo.copyattribute)
}

function Check-Command($cmdname) # checks if cmdlet is loaded/installed
{
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

Write-Debug "Using Get-ADUser cmdlet..."
try
{
    $c = 0
    $user = $null
    $groups = $null
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
                0 { $errorstr = "Unable to reach $($env:LOGONSERVER.Replace('\','')  + "." + $env:USERDNSDOMAIN)" }
                1 { $errorstr = "Unable to reach $($global:DCs[$c]), using $($env:LOGONSERVER.Replace('\','')  + "." + $env:USERDNSDOMAIN)" }
                default {  $errorstr = "Unable to reach $($global:DCs[$c]),trying next DC in config file..." }
            }
            Write-Debug $errorstr
            $c++
        }
    }

    if($user)
    {
        $user | Add-Member -MemberType NoteProperty -Name objectGUID -Value (($user.ObjectGUID.ToByteArray() | foreach { $_.ToString("X2") }) -join '' ) -Force
        $global:aliases | Foreach-Object { Add-Member -InputObject $user -MemberType AliasProperty -Name $_.name -Value $_.prop -Force }
     
        # copy attribute to clipboard
        if($modifer -eq 'c')
        {
            $user.($global:copyattribute.name).Replace($global:copyattribute.omit,"") | Set-Clipboard
            Write-Debug "copied $($global:copyattribute.name) to clipboard"
        }

        $user | Select -Property * -ExcludeProperty $($global:aliases.prop + ("memberOf"))

        if($user.memberOf.length -gt 0)
        {
            [int]$counter = 1
            $groups = $user.memberOf.replace("CN=", "") | Sort-Object { ($_ -match "$($global:groupformatting.filter -join '|')") } -Descending
            
            "------------------  Member Of ------------------"           
            foreach($group in $groups)
            {
                $groupColor = "cyan"
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