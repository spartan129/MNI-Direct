param (
    [switch] $SkipUpdateCheck
)

if (-not $SkipUpdateCheck) {
    $apiUrl = "https://raw.githubusercontent.com/spartan129/MNI-Direct/be662fd4d16d8f9ce8c63842a8d80d9bce064d99/MNIDirect_UM_Tool.ps1"

    $githubScriptContent = Invoke-WebRequest -Uri $apiUrl -UseBasicParsing

    if ($githubScriptContent -and $githubScriptContent.Content) {
        $githubScriptContent = $githubScriptContent.Content

        $currentScriptPath = $MyInvocation.MyCommand.Path
        $currentScriptContent = Get-Content -Path $currentScriptPath -Raw

        if ($currentScriptContent -ne $githubScriptContent) {
            Set-Content -Path $currentScriptPath -Value $githubScriptContent
            Write-Host "The script has been updated to the latest version." -ForegroundColor Green
            & $currentScriptPath -SkipUpdateCheck
            exit
        } else {
            Write-Host "The script is already up-to-date." -ForegroundColor Green
        }
    } else {
        Write-Host "Failed to retrieve the script content from GitHub." -ForegroundColor Red
    }
}

# Rest of your script


Write-Host 'Please complete both credential checks'

# Check if the CredentialManager module is installed
$CredentialManagerInstalled = Get-Module -ListAvailable -Name CredentialManager

if ($CredentialManagerInstalled) {
    Write-Host 'Credential Manager has been found. Skipping Login'
    $CredentialName = "MyExchangeOnlineCredential"
    $Credential = Get-StoredCredential -Target $CredentialName
} else {
    $Credential = Get-Credential
}

# Check if the MSOnline module is installed, and install it if necessary
if (-not (Get-Module -ListAvailable -Name MSOnline)) {
    Install-Module -Name MSOnline -Scope CurrentUser -Force
}

# Connect to Microsoft 365 tenant
Connect-MsolService -Credential $Credential

# Check if the ExchangeOnlineManagement module is installed, and install it if necessary
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force
}

# Connect to Exchange Online
Connect-ExchangeOnline -Credential $Credential -ShowBanner:$false


function OnboardEmployee {

do {

	# Gather user information
	$email = Read-Host -Prompt "Enter user's email address"
	$branch = Read-Host -Prompt "Enter user's branch number (42, 43, 44, or 45)"
	$position = Read-Host -Prompt "Enter user's position (Sales, Branch Manager, or Nursery Manager)"
	$newPassword = 'Ch@ngeMe1!'
	# Validate branch number
	$validBranches = @(42, 43, 44, 45)
	if (-not ($branch -in $validBranches)) {
		Write-Host "Invalid branch number. Please provide a valid branch number (42, 43, 44, or 45)."
		exit
	}

	# Assign licenses based on position
	$licenseMapping = @{
		'Sales' = @('reseller-account:DYN365_BUSCENTRAL_ESSENTIAL', 'reseller-account:O365_BUSINESS_ESSENTIALS','reseller-account:POWER_BI_STANDARD','reseller-account:POWERAPPS_VIRAL')
		'Branch Manager' = @('reseller-account:DYN365_BUSCENTRAL_ESSENTIAL', 'reseller-account:POWER_BI_STANDARD','reseller-account:O365_BUSINESS_PREMIUM','reseller-account:POWERAPPS_VIRAL')
		'Nursery Manager' = @('reseller-account:DYN365_BUSCENTRAL_ESSENTIAL', 'reseller-account:POWER_BI_STANDARD','reseller-account:O365_BUSINESS_PREMIUM','reseller-account:POWERAPPS_VIRAL')
	}

	$assignedLicenses = $licenseMapping[$position]

	if (-not $assignedLicenses) {
		Write-Host "Invalid position. Please provide a valid position (Sales, Branch Manager, or Nursery Manager)."
		exit
	}

	foreach ($license in $assignedLicenses) {
		$userLicenses = (Get-MsolUser -UserPrincipalName $email).Licenses.AccountSkuId
		if ($license -notin $userLicenses) {
			Set-MsolUserLicense -UserPrincipalName $email -AddLicenses $license
		} else {
			Write-Host "User already has the $license license assigned. Skipping."
		}
	}

Set-MsolUser -UserPrincipalName $email -BlockCredential $false
Set-MsolUserPassword -UserPrincipalName $email -NewPassword $newPassword -ForceChangePassword $false
	# Assign email groups based on position and branch number
	$groupMapping = @{
		'Sales' = @{
			'42' = @('allstaff@mnidirect.com', 'purchasing-atl@mnidirect.com','branch42@mnidirect.com')
			'43' = @('allstaff@mnidirect.com', 'br43purchasing@mnidirect.com','branch43@mnidirect.com')
			'44' = @('allstaff@mnidirect.com', 'purchasing-atl@mnidirect.com','branch44@mnidirect.com')
			'45' = @('allstaff@mnidirect.com', 'br45purchasing@mnidirect.com','branch45@mnidirect.com')
		}
		'Branch Manager' = @{
			'42' = @('br42managers@mnidirect.com','allstaff@mnidirect.com', 'purchasing-atl@mnidirect.com','availability@mnidirect.com','safety@mnidirect.com','branch42@mnidirect.com','br42security@mnidirect.com')
			'43' = @('br43managers@mnidirect.com','allstaff@mnidirect.com', 'br43purchasing@mnidirect.com','availability@mnidirect.com','safety@mnidirect.com','branch43@mnidirect.com','br43security@mnidirect.com')
			'44' = @('br44managers@mnidirect.com','allstaff@mnidirect.com', 'purchasing-atl@mnidirect.com','availability@mnidirect.com','safety@mnidirect.com','branch44@mnidirect.com','br44security@mnidirect.com')
			'45' = @('br45managers@mnidirect.com','allstaff@mnidirect.com', 'br45purchasing@mnidirect.com','availability@mnidirect.com','safety@mnidirect.com','branch45@mnidirect.com')
		}
		'Nursery Manager' = @{
			'42' = @('br42managers@mnidirect.com','allstaff@mnidirect.com', 'purchasing-atl@mnidirect.com','availability@mnidirect.com','safety@mnidirect.com','branch42@mnidirect.com','br42security@mnidirect.com')
			'43' = @('br43managers@mnidirect.com','allstaff@mnidirect.com', 'br43purchasing@mnidirect.com','availability@mnidirect.com','safety@mnidirect.com','branch43@mnidirect.com','br43security@mnidirect.com')
			'44' = @('br44managers@mnidirect.com','allstaff@mnidirect.com', 'purchasing-atl@mnidirect.com','availability@mnidirect.com','safety@mnidirect.com','branch44@mnidirect.com','br44security@mnidirect.com')
			'45' = @('br45managers@mnidirect.com','allstaff@mnidirect.com', 'br45purchasing@mnidirect.com','availability@mnidirect.com','safety@mnidirect.com','branch45@mnidirect.com')
		}
	}
	$assignedGroups = $groupMapping[$position][$branch]

	if ($assignedGroups) {
		foreach ($group in $assignedGroups) {
			$groupMembers = Get-DistributionGroupMember -Identity $group | Select-Object -ExpandProperty PrimarySmtpAddress
			if ($email -notin $groupMembers) {
				Add-DistributionGroupMember -Identity $group -Member $email
			} else {
				Write-Host "User is already a member of the $group group. Skipping."
			}
		}
	}
	else {
		Write-Host "Invalid position or branch number. Please provide valid inputs."
		exit
	}

	Write-Host "User onboarding process completed successfully."

	$continueOnboarding = Read-Host -Prompt "Would you like to onboard another employee? (Y/N)"
} while ($continueOnboarding -eq 'Y' -or $continueOnboarding -eq 'y')
Write-Host "Onboarding complete."
Read-Host -Prompt "Press any key to continue..."
}

# Define offboarding function
function OffboardEmployee {

do {
    # Prompt for user email and new password
    $userEmail = Read-Host -Prompt "Enter the email address of the user to be offboarded"
    $newPassword = Read-Host -Prompt "Enter the new password for the user"

    # Display the username and password for confirmation
    Write-Host "Please confirm the following information:"
    Write-Host "User email: $userEmail"
    Write-Host "New password: $newPassword"

    # Ask for confirmation before proceeding
    $confirmation = Read-Host -Prompt "To proceed with offboarding, type 'Y'"
    if ($confirmation -eq "Y" -or $confirmation -eq "y") {
        # Block sign-in for the user
        Set-MsolUser -UserPrincipalName $userEmail -BlockCredential $true

        # Reset the user's password
        Set-MsolUserPassword -UserPrincipalName $userEmail -NewPassword $newPassword -ForceChangePassword $false

        # Get the user's current licenses
        $user = Get-MsolUser -UserPrincipalName $userEmail
        $currentLicenses = $user.Licenses.AccountSkuId

        # Define the licenses to keep
        $licensesToKeep = @(
            "reseller-account:O365_BUSINESS_ESSENTIALS",
            "reseller-account:O365_BUSINESS_PREMIUM"
        )

        # Remove licenses except for the ones to keep
        foreach ($license in $currentLicenses) {
            if ($license -notin $licensesToKeep) {
                Set-MsolUserLicense -UserPrincipalName $userEmail -RemoveLicenses $license
            }
        }

        Write-Host "Offboarding completed for user: $userEmail"
    } else {
        Write-Host "Offboarding process canceled."
    }

    # Ask if another employee should be offboarded
    $continueOffboarding = Read-Host -Prompt "Would you like to offboard another employee? Y/N"
} while ($continueOffboarding -eq "Y" -or $continueOffboarding -eq "y")

Write-Host "Offboarding complete."
Read-Host -Prompt "Press any key to continue..."
}

#Define Pull Distribution List function
# Define Pull Distribution List function
# Define Pull Distribution List function
function PullDistributionList {
    Write-Host "Retrieving Distribution List"
    # Retrieve all distribution groups in the Exchange environment
    $AllGroups = Get-DistributionGroup

    # Initialize an empty array to store the results
    $Result = @()

    # Loop through each distribution group found
    foreach ($Group in $AllGroups) {
        # Retrieve the members of the current distribution group
        $Members = Get-DistributionGroupMember -Identity $Group.PrimarySmtpAddress

        # Initialize a flag to indicate if the group contains a member with the mccorklenurseries.com domain
        $containsMccorkleMember = $false

        # Loop through each member of the current distribution group
        foreach ($Member in $Members) {
            # Check if the email domain is mccorklenurseries.com
            if ($Member.PrimarySmtpAddress -match "@mccorklenurseries.com$") {
                $containsMccorkleMember = $true
                break
            }
        }

        # If the group does not contain a member with the mccorklenurseries.com domain, add the group and its members to the result
        if (!$containsMccorkleMember) {
            foreach ($Member in $Members) {
                # Create a new custom object with the group and member properties
                $Result += New-Object PSObject -Property @{
                    'GroupName' = $Group.DisplayName # Display name of the group
                    'GroupEmail' = $Group.PrimarySmtpAddress # Email address of the group
                    'MemberName' = $Member.DisplayName # Display name of the member
                    'MemberEmail' = $Member.PrimarySmtpAddress # Email address of the member
                }
            }
        }
    }

    Write-Host "List Saved to DistributionGroupsAndMembers CSV File"
    # Export the result array to a CSV file, without type information and using UTF-8 encoding
    $Result | Export-Csv -Path "$PSScriptRoot\DistributionGroupsAndMembers.csv" -NoTypeInformation -Encoding UTF8
    Read-Host -Prompt "Press any key to continue..."
}



#Define Pull License List function
function PullLicenseList {
Write-Host "Retrieving License List"
# Retrieve all users from the Office 365 tenant
$AllUsers = Get-MsolUser -All

# Create an empty array to store the license information
$Result = @()

# Iterate through each user in the list of all users
foreach ($User in $AllUsers) {
    # Get the licenses assigned to the current user
    $Licenses = $User.Licenses

    # Iterate through each license assigned to the current user
    foreach ($License in $Licenses) {
        # Create a new object with the user's name, email, and license name, and add it to the result array
        $Result += New-Object PSObject -Property @{
            'UserName'    = $User.DisplayName
            'UserEmail'   = $User.UserPrincipalName
            'LicenseName' = $License.AccountSkuId
        }
    }
}
Write-Host "License List saved to UserLicenses CSV File "
# Export the result array to a CSV file named "UserLicenses.csv"
$Result | Export-Csv -Path "$PSScriptRoot\UserLicenses.csv" -NoTypeInformation -Encoding UTF8

Read-Host -Prompt "Press any key to continue..."

}

function DisplayDisclaimer {
    $disclaimer = @"
  __| |________________________________________| |__
 (__   ________________________________________   __)
    | |               MNI DIRECT               | |
    | |________________________________________| |
    | |     This script is designed for the    | |                        
    | |     exclusive use of MNI Direct for    | |                       
    | |      managing user onboarding and      | |                        
    | |         offboarding processes.         | |                         
    | |                                        | |                        
    | |     DISCLAIMER: Unauthorized use of    | |                        
    | |    this script is strictly prohibited. | |                        
    | |________________________________________| |
    |____________________________________________|
"@

    Write-Host -ForegroundColor White $disclaimer
    Write-Host -NoNewline -ForegroundColor White "Do you agree to the terms? (Y/N): "
    $userAgreement = Read-Host

    return $userAgreement
}

# Check for user agreement
do {
    $agreement = DisplayDisclaimer
} while ($agreement -notmatch '^[Yy]$')



# Main loop
do {
	#clears screen
	Clear-Host

    # Present the user with available options
    $menu = @"
  __| |________________________________________| |__
 (__   ________________________________________   __)
    | |                                        | |
    | |     MNI DIRECT USER MANAGEMENT TOOL    | |   
    | |========================================| |
    | |                                        | |   
    | |    1. Onboard Employee                 | |   
    | |    2. Offboard Employee                | |   
    | |    3. Pull Distribution List           | |   
    | |    4. Pull License List                | |   
    | |    5. Exit                             | |   
    | |                                        | |   
    | |========================================| |
    | |       wWWWw               wWWWw        | |
    | | vVVVv (___) wWWWw         (___)  vVVVv | |
    | | (___)  ~Y~  (___)  vVVVv   ~Y~   (___) | |
    | |  ~Y~   \|    ~Y~   (___)    |/    ~Y~  | |
    | |  \|   \ |/   \| /  \~Y~/   \|    \ |/  | |
    | | \\|// \\|// \\|/// \\|//  \\|// \\\|///| |
    | |^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^| |
  __| |________________________________________| |__
 (__   ________________________________________   __)
    | |                                        | | 
"@

    Write-Host -ForegroundColor White $menu
	Write-Host -NoNewline -ForegroundColor White "Enter the number corresponding to the desired action: "
    
    # Read user input
    $userInput = Read-Host

    # Execute the chosen option
    switch ($userInput) {
        '1' {
            OnboardEmployee
        }
        '2' {
            OffboardEmployee
        }
        '3' {
            PullDistributionList
        }
        '4' {
            PullLicenseList
        }
        '5' {
            Write-Host "Exiting, have a wonderful day!..."
			Write-Host "The following command is asking to disconnect from exchange online. Respond Y"
			# Disconnect from Exchange Online
			Disconnect-ExchangeOnline
            exit
        }
        default {
            Write-Host "Invalid option. Please enter a valid number."
        }
    }
} while ($true)
