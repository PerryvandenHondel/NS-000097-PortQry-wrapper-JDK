<#
.Synopsis
    Script to test firewall rules and connectivity between Domain Controllers. 
.DESCRIPTION
    Powershell script written by Javy de Koning (JavydeKoning@gmail.com) for 
    SSC-AD @ Nederlandse Spoorwegen. Script can be used to verify that the 
    required firewall rules are in place between domain controllers. For the 
    best results execute on the local domain. 
.PARAMETER Domains
    Specifies one or multiple external domain(s). (Domains different from the
    computers local domain.) Keep in mind that firewall rules might prevent you 
    from discovering domain controllers in the external domain or connected 
    trusted/trusting domains.
.PARAMETER PortQryExe
    Specify the location of "PortQry.exe". If you do not specify the script will 
    use the default location which is the script directory. You can download 
    PortQryV2 from: http://www.microsoft.com/en-us/download/details.aspx?id=17148 
.PARAMETER IncludeTrusts
    Specify if you want to check connectivity to domain controllers in trusted
    and trusting domains as well.
.PARAMETER LogToFile
    Use this parameter if you want output to be logged to an output file. 
.EXAMPLE
    Get-JKPortScan 
.EXAMPLE
    Get-JKPortScan -LogToFile -IncludeTrusts
.OUTPUTS
    Logging for use in Splunk.
.NOTES
    Version 0.1 - Initial Version JavydeKoning@gmail.com
    Version 0.2 - Rewritten Certain Get-JKDomainControllers.
    Version 0.3 - Debugging and rewritten for PoSH v2 compatibility
    Version 1.0 - Final Version
    Version 1.1 - BugFixes (August 6th, 2014)
    Version 1.2 - Output Changes (Dir tree structure)
    Version 1.3 - Changed FQDN in output to Hostname
    Version 1.4 - 6-Okt-2014; Output changed for 'export-csv' compatibility, removed UDP checks.
    Version 1.5 - BugFixes
    Version 1.6 - 21-Okt-2014; Added additional checks for WSUS etc.
    Version 1.7 - 21-Okt-2014; Removed SPLUNK functions and added commments. 
.FUNCTIONALITY
    This command performs a portscan for Active Directory requierd ports to all Domain Controllers 
    in the local Domain (To scan a different domain use the -Domains paraneter). You can also scan "Trusted"
    and "Trusting" domains by using the -IncludeTrusts parameter. 
#>

#Set the default PortQry.exe location to the script directory. 
$ScriptPath = "$($MyInvocation.InvocationName | Split-Path)"
If (!($ScriptPath.SubString($ScriptPath.Length-1,1) -eq "\")) {
    $PQ = "$ScriptPath\PortQry.exe"
} else {
    $PQ = $ScriptPath+"PortQry.exe"
} 

#This function will call PortQry and return the result+output. 
function Test-JKPortQry ($PortQryExe,$Server,$Port,$Protocol) {
    #Generate Commandline string
    $cmd = "$PortQryExe -n $Server -p $Protocol -e $Port"
    
    #Execute $cmd, store non-empty lines in $Output 
    $Output = & "$PortQryExe" -n "$Server" -p "$Protocol" -e "$Port" | Where {$_}
                    
    #translate output to LISTENING/FILTERED. Store in $Result
    $Result=$null
    switch -Wildcard ($Output[-1]) {
        "==== End of RPC Endpoint Mapper query response ====" {$Result = 'LISTENING'}
        "*LISTENING or FILTERED"                              {$Result = 'FILTERED'}
        "*LISTENING"                                          {$Result = 'LISTENING'}
        "*did not respond to LDAP query"                      {$Result = 'FILTERED'}
        "======== End of LDAP query response ========"        {$Result = 'LISTENING'}
        "*: FILTERED"                                         {$Result = 'FILTERED'}
        default                                               {$Result = 'UNKNOWN'}
    }
     
    #Create new object from properties. Return the object.                 
    $Props = @{
        'Server' = $Server;
        'Prot'   = $Protocol;
        'Port'   = $Port;
        'Output' = $Output[-1];
        'Result' = $Result;
    }

    $Obj = new-object -TypeName PSObject -Property $Props
    Return $Obj
}

#Function to read domaintrusts using dotnet. 
function Get-JKDomainTrusts ($DomainName) {
    $Trusts = @()
    $Context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$DomainName) 
    Try{
        $Domain = [system.directoryservices.activedirectory.domain]::GetDomain($context) 
    }   
    Catch{
        Write-Warning "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): Could not access domain: `"$Domain`" to retrieve domain trusts"
        Write-Verbose "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): Could not access domain: `"$Domain`" to retrieve domain trusts"
    }
    
    ForEach ($Trust in $Domain.GetAllTrustRelationships()) {
        $Trusts += $Trust.TargetName
        }
    Return $Trusts
}

#Function to read Forest trusts using dotnet. 
function Get-JKForestTrusts ($DomainName) {
    $Trusts = @()
    $Context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$DomainName) 
    Try{
        $Domain = [system.directoryservices.activedirectory.domain]::GetDomain($context)
    }   
    Catch{
        Write-Warning "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): Could not access domain: `"$Domain`" to retrieve forest trusts"
        Write-Verbose "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): Could not access domain: `"$Domain`" to retrieve forest trusts"
    }
    $Forest = $Domain.Forest 
    ForEach ($Trust in $Forest.GetAllTrustRelationships()) {
        $Trusts += $Trust.TargetName
        }
    Return $Trusts
}

#Function to retrieve all domain controllers from a specific domain. 
function Get-JKDomainControllers ($Domains) {
    $DomainControllers = @()
    ForEach ($Domain in $Domains) {
        $LdapFailed=$false

        Write-Verbose "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): Searching DC's in $Domain"
        $Context = new-object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain","$Domain")        
    
        Try{
            $Domain = [system.directoryservices.activedirectory.domain]::GetDomain($context)
            }
        Catch{
            Write-Warning "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): Could not access domain: `"$Domain`", spelling correct? Firewall Closed? Selective authentication enabled?"
            Write-Verbose "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): Searching DC's in $Domain FAILED"
            $LdapFailed = $true
            }
        
        if ($LdapFailed = $true) {
            $DC_DNS = ([System.Net.Dns]::GetHostByName($Domain)).AddressList | Select-Object $_.IPAddressToString
            foreach ($DC in $DC_DNS) {$DomainControllers += $DC.IPAddressToString} 
        }

        #Loop through Domain Controllers, Store in $Servers
        ForEach($DomainController in $Domain.DomainControllers){
            #Prevent empty entries in array.
            if ($DomainController.Name) {
                [String[]]$DomainControllers += $DomainController.Name
            }
        }
    }
    Return $DomainControllers
}

#Main function to execute.
function Get-JKPortScan
{
    [CmdletBinding(DefaultParameterSetName='Domain')]  
    #Defining input parameters
    Param(
        [Parameter(
            ParameterSetName='Domain',
            Mandatory=$False,
            ValueFromPipeLine=$True,
            Position=0,
            HelpMessage='Please enter one or more domain(s) by FQDN.')]

        [ValidatePattern(
            '^[a-zA-Z0-9]+(\.[a-zA-Z0-9-]+)*(\.[A-Za-z]+)$'
        )]
        #If no domain was specified use the machine's domainname                       
        [String[]]$Domains = (gwmi win32_computersystem).domain,

        #Location of PortQry.exe Download: http://www.microsoft.com/en-us/download/details.aspx?id=17148
        [Parameter()]
        [string]$PortQryExe = $PQ,

        [Parameter()]
        [switch]$IncludeDomainTrusts,

        [Parameter()]
        [switch]$IncludeForestTrusts
    )

    #Execute at the beginning of the script
    Begin {
        $CompName     = $env:computername
        $SourceIP = (Get-WmiObject -class win32_NetworkAdapterConfiguration -Filter 'ipenabled = "true"').ipaddress[0]

        Write-Verbose -Message "Script started on $CompName by user $(whoami)"
        
        #Validate that PortQry.exe exists, if not found exit
        if(-NOT(Test-Path $PortQryExe)) {
            Write-Warning "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): $PortQryExe does not exist, supply correct path using the -PortQryExe parameter"
            break
            }

        #empty arrays for commandline output and domain controllers
        $Array = @()
        $Servers =@()
        $AllDomains = @()

        #Define ports according to http://support.microsoft.com/kb/179442
        $Ports = @(88,"TCP","KERB"),
                 @(135,"TCP","RPC"),
                 @(389,"TCP","LDAP"),
                 @(445,"TCP","SMB"),
                 @(464,"TCP","K-PWD"),
                 @(3268,"TCP","GC"),
                 @(3269,"TCP","GC_SSL")
        
        #Additional port checks.
        $AdditionalPorts =  @("vm70as003.rec.nsint",80,"TCP","WSUS"),
                            @("vm70as003.rec.nsint",443,"TCP","WSUS"),
                            @("vm70as004.rec.nsint",5723,"TCP","SCOM"),
                            @("vm70as003.rec.nsint",8081,"TCP","MCAFEE"),
                            @("vm70as003.rec.nsint",8443,"TCP","MCAFEE"),
                            @("vm70as003.rec.nsint",8444,"TCP","MCAFEE"),
                            @("vm70as003.rec.nsint",8530,"TCP","WSUS"),
														@("vm70as006.rec.nsint",445,"TCP","SMB")
    } # END Begin

    Process {
        #Check if the user has set the Domain or Forest Trust parameters. If parameter is set, get trusted/trusting domains and add to the set of domains to check. 
        if ($IncludeDomainTrusts.IsPresent) {
            foreach ($Domain in $Domains) {$AllDomains += Get-JKDomainTrusts -DomainName $Domain}
        } #END IF

        if ($IncludeForestTrusts.IsPresent) {
            foreach ($Domain in $Domains) {$AllDomains += Get-JKForestTrusts -DomainName $Domain}
        } #END IF
        
        #Add Domains supplied using parameter. 
        $AllDomains += $Domains
        
        #Remove duplicate domains (Multiple domains could trust the same domain, creating duplicates)
        $AllDomains = $AllDomains | Sort-Object -Unique
        Write-Verbose "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): Found $($AllDomains.Count) Domain(s)"
        
        #Lookup DC's in all domains.
        $Servers = Get-JKDomainControllers -Domains $AllDomains
        Write-Verbose "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): Found $($Servers.Count) Domain Controllers in $($AllDomains.Count) domains"

        #$i is used as counter for the total progress bar (servers*ports = total)
        $i=1

        #$si is used for server counter. 
        $si=1
        
        #Get total number of servers and ports. Multiply to get a total number of actions to perform (scan x ports on y servers for a total of z actions)
        $NoServers=$Servers.Count
        $NoPorts=$Ports.Count
        $total=($NoServers * $NoPorts) + $AdditionalPorts.Count
        
        ForEach ($Server in $Servers) {
                #$pi is used as port counter
                $pi=1
                ForEach ($P in $Ports) {
                    #Create a progress bar to monitor script progression
                    write-progress -Activity "Portscanning $server (Server $si out of $NoServers)" -Status "Scanning $($P[2]) ($($P[1])) on port $($P[0])  (Port $pi out of $NoPorts)" -PercentComplete ($i/$total*100)
                    
                    #Call PortQry function, supply PortQry.exe location, Destination, Port and Protocol.
                    Write-Verbose "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): Testing $Server Port: $($P[0]) Protocol: $($P[1])"
                    $PortScanResult = Test-JKPortQry -PortQryExe $PortQryExe -Server $Server -Port $($P[0]) -Protocol $($P[1])
                    
                    if ($PortScanResult.Server -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
                        $DestinationIP = $Server
                    }
                    
                    else {
                        $DestinationIP = (([System.Net.Dns]::GetHostByName($Server)).AddressList) | Select-Object IPAddressToString
                        $DestinationIP = $DestinationIP.IPAddressToString
                    }
                    
                    $Description = $($P[2])

                    #Store properties in Object, add Object to array. 
                    $Props = @{
                        'Source'        = $CompName;
                        'SourceIP'      = $SourceIP;
                        'Destination'   = $Server;
                        'DestinationIP' = ([string]::Join(";",$DestinationIP));
                        'Protocol'      = $PortScanResult.Prot;
                        'Port'          = $PortScanResult.Port;
                        'Desc'          = $Description;
                        'Output'        = $PortScanResult.Output;
                        'Result'        = $PortScanResult.Result;
                    }
                    
                    $Obj    = new-object -TypeName PSObject -Property $Props
                    $Array += $Obj | Select-Object Source, SourceIP, Destination, DestinationIP, Protocol, Port, Desc, Output, Result
                    
                    #Increment counters for progress bar
                    $i++
                    $pi++
                    }
            $si++ 
            } # END foreach server
        
        #Reset port counter
        $pi=1
        ForEach ($Port in $AdditionalPorts) {         
            write-progress -Activity "Portscanning additional port $Port $pi out of $($AdditionalPorts.Count)" -Status "Scanning $($Port[3]) ($($P[2])) on port $($P[1])" -PercentComplete ($i/$total*100)
            Write-Verbose "$(Get-Date -Format 'yyyyMMdd-hh:mm:ss'): Testing $($Port[0]) Port: $($Port[1]) -Protocol: $($Port[2])"
            
            $PortScanResult = Test-JKPortQry -PortQryExe $PortQryExe -Server $($Port[0]) -Port $($Port[1]) -Protocol $($Port[2])

            if ($PortScanResult.Server -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") {
                $DestinationIP = $($Port[0])
            }
            else {
                $DestinationIP = (([System.Net.Dns]::GetHostByName($($Port[0]))).AddressList) | Select-Object IPAddressToString
                $DestinationIP = $DestinationIP.IPAddressToString
            }

            $Destination = $($Port[0])
            $Description = $($Port[3])
                    
            #Store properties in Object, add Object to array. 
            $Props = @{
                'Source'        = $CompName;
                'SourceIP'      = $SourceIP;
                'Destination'   = $Destination;
                'DestinationIP' = ([string]::Join(";",$DestinationIP));
                'Protocol'      = $PortScanResult.Prot;
                'Port'          = $PortScanResult.Port;
                'Desc'          = $Description;
                'Output'        = $PortScanResult.Output;
                'Result'        = $PortScanResult.Result;
            }
            $Obj = new-object -TypeName PSObject -Property $Props
            $Array += $Obj | Select-Object Source, SourceIP, Destination, DestinationIP, Protocol, Port, Desc, Output, Result
            
            #Increment counters for progress bar
            $i+=1 
            $pi+=1 
        }
    } #END Process

    End {
        #Output array
        Return $Array
        #Clear Progressbar
        Write-Progress -Completed -Activity "Completed" -status "Completed"
    }
}


#!!! - Indien men dit script wil installeren als CMDLET uncomment dan onderstaande regel en sla het script op als 
#!!!   NAAM\NAAM.ps1m in een PSModule path ($env:PSModulePath). Vervolgens importeren met "Import-Module"

#Export-ModuleMember -Function Get-JKPortScan -Variable ErrorLogPreference


#!!! - Indien men dit script uitvoeren als script file roep dan "Get-JKPortScan" hieronder aan zoals beschreven in 
#!!!   de help (Vanaf regel 121). Nog even de parameters op een rij: 
#!!!   -Verbose: Standaard PoSH parameter om verbose output op het scherm weer te geven
#!!!   -IncludeForestTrusts: Scan ook DC's in Domains verbonden via een forest trust
#!!!   -IncludeDomainTrusts: Scan ook DC's in Domains verbonden via een domain trust 
#!!!   -LogToFile: Sla de output op in het verzochte formaat in een logfile. Welke file dat is word bovenaan in het script gezet. Default is <home-directory>\JKErrorLog.txt
#!!!   -PortQryExe: Geef het pad op naar PortQry.exe
#!!!   -Domains: Scan de opgegeven domeinen (i.e. -Domains "prod.ns.nl","test.ns.nl")

Get-JKPortScan -verbose -IncludeForestTrusts -IncludeDomainTrusts
