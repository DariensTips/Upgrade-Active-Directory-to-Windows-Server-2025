# Check the AD schema version
Get-ADObject (Get-ADRootDSE).schemaNamingContext -Property objectVersion

# Get list of all DCs in the domain
$DCs = (Get-ADDomainController -Filter *).HostName

# Run DcDiag on all DCs
dcdiag

# Run DcDiag on all domains in the forest
$allDomainsInForest = (Get-ADForest).Domains
foreach ($curDom in $allDomainsInForest) {dcdiag.exe /n:$curDom}

# Check replication status
repadmin /showrepl
repadmin /replsummary
Get-ADReplicationPartnerMetadata -Target * | Select Server,Partner,LastReplicationSuccess | Format-List
Get-ADReplicationFailure -Scope Forest

# Force replication between all DCs
Repadmin /syncall /AdeP

# Check DNS and DNS SRV records for domain controllers
$theDomain = (Get-ADDomain).DNSRoot
Resolve-DnsName $theDomain
Resolve-DnsName _ldap._tcp.dc._msdcs.$theDomain -Type SRV

# Check SYSVOL and NETLOGON shares and their contents on all DCs
$DCs | ForEach-Object {Invoke-Command -ComputerName $_ -ScriptBlock {
        Get-SmbShare -Name SYSVOL, NETLOGON | select-object name,path,description }
    Get-ChildItem \\$_\SYSVOL | select-object fullname,exists
    Get-ChildItem \\$_\NETLOGON  | select-object fullname,exists } 

# Check time synchronization status with the PDC Emulator
$pdc = (Get-ADDomain).PDCEmulator
w32tm /monitor /computers:$pdc
$DCs | ForEach-Object {Invoke-Command -ComputerName $_ -ScriptBlock {$pdc = (Get-ADDomain).PDCEmulator ; w32tm /monitor /computers:$pdc}}

# Check Network Category reflects DomainAuthenticated
Get-NetConnectionProfile

# Check DFSR service status
Add-WindowsFeature -Name RSAT-DFS-Mgmt-Con

# Check DFSR replication status and force sync of SYSVOL
dfsrdiag pollad
dfsrdiag replstate
dfsrdiag syncnow /partner: $pdc /rgname:"Domain System Volume" /time:15

# Clear Event Logs on all DCs
$DCs = (Get-ADDomainController -Filter *).HostName
Invoke-Command -ComputerName $DCs -ScriptBlock {
    cd "C:\Windows\System32"
    $allEvents = wevtutil.exe el
    $allEvents | ForEach-Object {wevtutil.exe cl $_}
}

# Move FSMO roles to a specific DC
Move-ADDirectoryServerOperationMasterRole -Identity DTDC03 -OperationMasterRole 0,1,2,3,4

# Check DNS client server addresses on a specific DC
Invoke-Command -ComputerName dtdc01 `
    -ScriptBlock {Get-DnsClientServerAddress | `
        Select-Object elementname,serveraddresses}

# Set DNS client server addresses on a specific DC and clear DNS cache
Invoke-Command -ComputerName dtdc02 `
    -ScriptBlock {Set-DnsClientServerAddress -InterfaceAlias "Ethernet" `
        -ServerAddresses ("10.12.25.15","10.12.25.12","10.12.25.13") ; `
        Get-DnsClientServerAddress | Select-Object elementname,serveraddresses ; ` 
        Clear-DnsClientCache}

# Install AD DS role on a new server
Add-WindowsFeature -Name AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools

# Get necessary credentials for domain or forest operations
$credential = Get-Credential "professa.ea@$theDomain"

# Promote the server to a domain controller in an existing domain
Install-ADDSDomainController `
    -DomainName $theDomain `
    -InstallDns:$true `
    -ReplicationSourceDC $pdc `
    -DatabasePath "C:\Windows\NTDS" `
    -LogPath "C:\Windows\NTDS" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -Credential $credential

# Post-promotion quick checks
dcdiag /test:advertising
netdom query fsmo
Get-SmbShare -Name SYSVOL,NETLOGON

# Set DHCP server option 006 to set DNS server order
Set-DhcpServerv4OptionValue -ComputerName dtdhcp01 `
    -ScopeId 10.12.25.0 `
    -DnsServer "10.12.25.15","10.12.25.13","10.12.25.12"

# Demote a domain controller and remove it from the domain
Uninstall-ADDSDomainController -DemoteOperationMasterRole:$true -RemoveDnsDelegation:$true

# Uninstall AD DS role and DNS role from the server
Remove-WindowsFeature AD-Domain-Services,DNS

# Remove the server from the domain and shutdown computer
Remove-Computer -WorkgroupName "Gone"
Stop-Computer -Force

# Check the Domain Functional Level from all DCs
$DCs = (Get-ADDomainController -Filter *).HostName
$DCs | ForEach-Object {Get-ADDomain -Server $_ | Select-Object DomainMode}

# Check the Forest Functional Level from all DCs
$DCs = (Get-ADDomainController -Filter *).HostName
$DCs | ForEach-Object {Get-ADForest -Server $_ | Select-Object ForestMode}

# Check FSMO role holders
netdom query fsmo
Get-ADDomain | Select-Object PDCEmulator,RIDMaster,InfrastructureMaster | Format-List
Get-ADForest | Select-Object SchemaMaster,DomainNamingMaster | Format-List

# Check the Domain and Forest Functional Levels from all DCs
$DCs = (Get-ADDomainController -Filter *).HostName
$DCs | ForEach-Object {Get-ADDomain -Server $_ | Select-Object DomainMode}
$DCs | ForEach-Object {Get-ADForest -Server $_ | Select-Object ForestMode}

# List all DCs in the forest with their OS and domain
$domains = (Get-ADForest).Domains
$allDCs = foreach ($domain in $domains) {Get-ADDomainController -Filter * -Server $domain}
$allDCs | Select-Object name,operatingsystem,domain

# Raise the Domain Functional Level to Windows Server 2025 (Windows2025Domain)
$dtDomain = (Get-ADDomain).dnsroot
$dtDomainMode = "Windows2025Domain"
Set-ADDomainMode -Identity $dtDomain -DomainMode $dtDomainMode

# Raise the Forest Functional Level to Windows Server 2025 (Windows2025Forest)
$dtForest = (Get-ADForest).name
$dtForestMode = "Windows2025Forest"
Set-ADForestMode -Identity $dtForest -ForestMode $dtForestMode

# Check the AD database page size on all DCs
$objClass="(ObjectClass=nTDSDSA)"
$adsiDomConf="CN=Configuration,DC=dariens,DC=tips"
Get-ADObject -LDAPFilter $objClass -SearchBase $adsiDomConf -properties msDS-JetDBPageSize `
    | Format-List distinguishedName,msDs-JetDBPageSize

# Enable the 32k page size feature in the domain
$theDomain = "dariens.tips"
$pdc = (Get-ADDomain).PDCEmulator
$ADOptFeature = "Database 32k pages feature"
$ADOScope = "ForestOrConfigurationSet"
Enable-ADOptionalFeature -Identity $ADOptFeature -Scope $ADOScope -Server $pdc -Target $theDomain
