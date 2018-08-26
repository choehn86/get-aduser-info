# getadinfo
[PowerShell] Uses Get-ADUser cmdlet to return Active Directory User information in a 'pretty' manner
This was inspired by a constant need to view specific attributes while comparing users between Oracle OIM and AD for reconciliation jobs between the two systems.  I find the GUI to be cumbersome reviewing this data and I was tired of configuring Get-ADUser in the command line.  It has been re-tooled to use a JSON config file for customization and scalability.
