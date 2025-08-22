Function Invoke-AddVulnerableTemplateESC1 {

<#

.DESCRIPTION
Add a new Certificate Template to the Active Directory Certificate Services. This template is vulnerable to ESC1. 

.PARAMETER Domain
Specifies the name of the Active Directory domain.

.PARAMETER TemplateName
Specifies the name of the template that will be created. 

.PARAMETER CAName
Specifies the name of the Certificate Authority, where the template will be created. 

.EXAMPLE
Invoke-AddVulnerableTemplateESC1 -Domain cybertron.local -templateName 'ESC1' -CAName 'RootCA' 
#>

    Param(
        [Parameter(Mandatory=$true,HelpMessage="Enter the domain name, e.g. example.local")]
        [ValidateNotNullOrEmpty()]
        [string]$domain,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the new Certificate Template, e.g. 'VulnerableTemplate'")]
        [ValidateNotNullOrEmpty()]
        [string]$templateName,

        [Parameter(Mandatory=$true,HelpMessage="Enter the name of the Certificate Authority, e.g. 'RootCA'")]
        [ValidateNotNullOrEmpty()]
        [string]$CAName
        )

    # Split the domain into the name and the TLD
    $domainName = $domain.Split(".")[0]
    $tld = $domain.Split(".")[1]
    $templateOID = [System.Guid]::NewGuid().ToString()

    # Set the config path
    $configPath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$domainName,DC=$tld"
    $templates = [ADSI]$configPath

    # Create a new template
    Write-Host '[+] Creating new Certificate Template...' 
    $newTemplate = $templates.Create("pKICertificateTemplate", "CN=$templateName")

    # Copy key attributes
    $newTemplate.Put("displayName", $templateName)
    $newTemplate.Put("flags", 131642)
    $newTemplate.Put("revision", 100)
    $newTemplate.Put("pKIDefaultKeySpec", 1)
    $newTemplate.Put("pKIMaxIssuingDepth", 0)
    $newTemplate.Put("msPKI-Enrollment-Flag", 9)
    $newTemplate.Put("msPKI-Private-Key-Flag", 16842768)
    $newTemplate.Put("msPKI-Certificate-Name-Flag", 1)
    $newTemplate.Put("msPKI-Minimal-Key-Size", 2048)
    $newTemplate.Put("msPKI-Template-Schema-Version", 2)
    $newTemplate.Put("msPKI-Template-Minor-Revision", 6)
    $newTemplate.Put("msPKI-RA-Signature", 0)

    $templateOID = "1.3.6.1.4.1.311.21.8.12404716.16511244.12011432.3773314.9777680.179.74311955.19915713"
    $newTemplate.Put("msPKI-Cert-Template-OID", $templateOID)

    # Set EKUs
    $newTemplate.PutEx(2, "pKIExtendedKeyUsage", @(
        "1.3.6.1.5.5.7.3.2",
        "1.3.6.1.5.5.7.3.4",
        "1.3.6.1.4.1.311.10.3.4"
    ))

    # Set Application Policies
    $newTemplate.PutEx(2, "msPKI-Certificate-Application-Policy", @(
        "1.3.6.1.5.5.7.3.2",
        "1.3.6.1.5.5.7.3.4",
        "1.3.6.1.4.1.311.10.3.4"
    ))

    # Set Key Usage
    $newTemplate.Put("pKIKeyUsage", [byte[]](0xA0, 0x00))

    # Set Critical Extensions
    $newTemplate.PutEx(2, "pKICriticalExtensions", @("2.5.29.7", "2.5.29.15"))

    # Set Default CSPs
    $newTemplate.PutEx(2, "pKIDefaultCSPs", @(
        "2,Microsoft Base Cryptographic Provider v1.0",
        "1,Microsoft Enhanced Cryptographic Provider v1.0"
    ))

    # Copy validity and renewal period from User template
    $userTemplateDN = "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$domainName,DC=$tld"
    $userTemplate = [ADSI]"LDAP://$userTemplateDN"
    $validityPeriod = $userTemplate."pKIExpirationPeriod"[0]
    $renewalPeriod = $userTemplate."pKIOverlapPeriod"[0]
   
    # Set validity period on newly created template
    $newTemplate.Put("pKIExpirationPeriod", $validityPeriod)
  
    # Set the renewal period on newly created template
    $newTemplate.Put("pKIOverlapPeriod", $renewalPeriod)

    $newTemplate.CommitChanges()
    Write-Host '[+] Created Certificate Template with OID' $templateOID

    # Create Security Descriptor -> Domain User with read and enroll rights
    $enterpriseAdminsSID = 
    $sd = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList " O:LAG:EAD:AI(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DA)(OA;;RPWPCR;0e10c968-78fb-11d2-90d4-00c04f79dc55;;DU)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;LA)(A;;LCRPLORC;;;AU)(A;CIID;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;EA)(A;CIID;CCLCSWRPWPLOCRSDRCWDWO;;;DA)"
    $sdBytes = New-Object byte[] ($sd.BinaryLength)
    $sd.GetBinaryForm($sdBytes, 0)

    # Write Security Descriptor to new certificate template
    Write-Host '[+] Writing Security Descriptor to new template...'
    Set-ADObject -Identity "CN=$templateName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$domainName,DC=$tld" -Replace @{nTSecurityDescriptor = $sdBytes}
    Write-Host '[+] Wrote Security Descriptor to new template'

    # Publish new certificate
    Write-Host '[+] Publishing new certificate to' $CAName
    $CADN = "CN=$CAName,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=$domainName,DC=$tld"
    $CA = [ADSI]"LDAP://$CADN"
    $currentTemplates = $CA.certificateTemplates

    # Add your template to the list
    $newTemplates = @("$templateName")
    if ($currentTemplates) {
        $newTemplates += $currentTemplates
    }

    $CA.certificateTemplates = $newTemplates
    $CA.CommitChanges()
    Write-Host '[+] Published new certificate!'
}