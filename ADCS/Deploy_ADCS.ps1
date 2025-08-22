Function Invoke-InstallADCS {

<#

.DESCRIPTION
Installs the Active Directory Certificate Services on the system, will also enable Web Enrollment.

.PARAMETER CAName
Specifies the name of the Certificate Authority.

.EXAMPLE
Invoke-InstallADCS -CAName 'RootCA' 
#>

    Param(
            [Parameter(Mandatory=$true,HelpMessage="Enter the name of the Certificate Authority, e.g. 'RootCA'")]
            [ValidateNotNullOrEmpty()]
            [string]$CAName
            )

    
    # Add the ADCS Windows feature
    Install-WindowsFeature Adcs-Cert-Authority
    Install-WindowsFeature ADCS-Web-Enrollment
    Install-WindowsFeature Web-Server

    # Install ADCS and enable Web Enrollment
    Install-AdcsCertificationAuthority -CAType "EnterpriseRootCA" -CACommonName $CAName -KeyLength 4096 -HashAlgorithmName SHA512 -Confirm
    Install-AdcsWebEnrollment -Confirm

    # Restart services
    Restart-Service certsvc
    Restart-Service w3svc
}