$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.SearchRoot = [adsi] "LDAP://$DC" 
        $objSearcher.PageSize = 1000
        $objSearcher.Filter = "(&(objectCategory=User)(samAccountName=$userID))"
        $objSearcher.SearchScope = "Subtree"

        $colResults = $objSearcher.FindAll()

        if(!$colResults.Count -lt 1)
        {
            #Write-Host ("Get-ADUser cmdlet not installed, using DirectorySearcher...")
            $user = New-Object PSObject

            foreach($p in $props)
            {
                $val = ''
                if( $colResults.Properties[$p].Count -gt 0 )
                {
                    switch($p)
                    {
                        'Enabled'      { $val = [string]!( (($colResults.Properties['useraccountcontrol'].Item(0)) -band 2) -eq 2) }
                        'objectguid'   { $val = (($colResults.Properties['objectGUID'].Item(0) | foreach { $_.ToString("X2") }) -join '' ) }
                        'memberOf'     { $val = $colResults.Properties['memberOf'].GetEnumerator() | foreach-object { $_ } }
                        default        { $val = $colResults.Properties[$p].Item(0) }
                    }
                    $user | Add-Member -MemberType NoteProperty -Name $p -Value $val
                }
            }

            $user

            # Display Groups
	        if($colResults.Properties.memberof.count -gt 0)
	        {
            	    "------------------  Member Of ------------------"
            	    $colResults.Properties.memberof
            	    "------------------------------------------------"
	        }
	        else
	        {
	    	    Write-Host("User is not a member of any groups!")
	        }
        }
        else
        {
            Write-Host "No results found!"
        }
