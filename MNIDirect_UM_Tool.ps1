#test 123
#Function to check User Credentials and import security modules
Function CredCheck{
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
}

#Function to set the background color and window size of the console
function SetConsoleAppearance {
    # Set the desired background color
    $backgroundColor = "Black"

    # Get the current console colors
    $consoleColors = $Host.UI.RawUI.ForegroundColor, $Host.UI.RawUI.BackgroundColor

    # Set the new background color
    $Host.UI.RawUI.BackgroundColor = $backgroundColor

    # Clear the console to apply the new background color
    Clear-Host

    # Set the desired window width and height
    $windowWidth = 56
    $windowHeight = 30

    # Set the desired buffer width and height
    $bufferWidth = 56
    $bufferHeight = 2000

    # Get the current console window and buffer size
    $currentWindowSize = $Host.UI.RawUI.WindowSize
    $currentBufferSize = $Host.UI.RawUI.BufferSize

    # Set the new console window and buffer size
    $newWindowSize = $currentWindowSize
    $newBufferSize = $currentBufferSize

    $newWindowSize.Width = $windowWidth
    $newWindowSize.Height = $windowHeight
    $newBufferSize.Width = $bufferWidth
    $newBufferSize.Height = $bufferHeight

    $Host.UI.RawUI.WindowSize = $newWindowSize
    $Host.UI.RawUI.BufferSize = $newBufferSize
}

#Function to update the script after a user prompt is given, connects to github to pull script update
function UpdateScript {
    # Ask the user if they would like to check for an update
    Clear-Host
    $checkForUpdate = Read-Host -Prompt "
       Would you like to check for an update? 
      This will close the script after updating. 
                    Type Y/N "

    if ($checkForUpdate.ToLower() -eq 'y') {
        # Set GitHub API URL to get the latest version of your script
        $apiUrl = "https://raw.githubusercontent.com/spartan129/MNI-Direct/main/MNIDirect_UM_Tool.ps1"

        try {
            # Get the content of the script from GitHub
            $githubScriptContent = Invoke-WebRequest -Uri $apiUrl -UseBasicParsing

            # Check if the script content is not empty
            if ($githubScriptContent -and $githubScriptContent.Content) {
                $githubScriptContent = $githubScriptContent.Content

                # Get the path of the currently running script
                $currentScriptPath = $MyInvocation.MyCommand.Path

                # Get the content of the currently running script
                $currentScriptContent = Get-Content -Path $currentScriptPath -Raw

                # Compare the content of the GitHub script and the current script
                if ($currentScriptContent -ne $githubScriptContent) {
                    # Update the current script with the content of the GitHub script
                    Set-Content -Path $currentScriptPath -Value $githubScriptContent

                    # Show a message that the script has been updated
                    Write-Host "The script has been updated to the latest version." -ForegroundColor Green

                    # Close the script after updating
                    exit
                } else {
                    Write-Host "The script is already up-to-date." -ForegroundColor Green
                }
            } else {
                Write-Host "Failed to retrieve the script content from GitHub." -ForegroundColor Red
                exit
            }
        } catch {
            Write-Host "An error occurred while trying to check for updates: $_" -ForegroundColor Red
            exit
        }
    }
}

#Function to set onboarding employee licenses and email groups
function OnboardEmployee {
    # Optimized groupMapping variable assignment
    $commonEmails = @{
        PurchasingATL = 'purchasing-atl@mnidirect.com'
        Availability  = 'availability@mnidirect.com'
        Safety        = 'safety@mnidirect.com'
    }

    $branches = @{
        '42' = @{
            Purchasing = $commonEmails.PurchasingATL
            Branch     = 'branch42@mnidirect.com'
            Managers   = 'br42managers@mnidirect.com'
            Security   = 'br42security@mnidirect.com'
        }
        '43' = @{
            Purchasing = 'br43purchasing@mnidirect.com'
            Branch     = 'branch43@mnidirect.com'
            Managers   = 'br43managers@mnidirect.com'
            Security   = 'br43security@mnidirect.com'
        }
        '44' = @{
            Purchasing = $commonEmails.PurchasingATL
            Branch     = 'branch44@mnidirect.com'
            Managers   = 'br44managers@mnidirect.com'
            Security   = 'br44security@mnidirect.com'
        }
        '45' = @{
            Purchasing = 'br45purchasing@mnidirect.com'
            Branch     = 'branch45@mnidirect.com'
            Managers   = 'br45managers@mnidirect.com'
        }
    }

    $roles = @(
        'Sales',
        'Branch Manager',
        'Nursery Manager'
    )

    $groupMapping = @{}

    foreach ($role in $roles) {
        $roleGroups = @{}
        
        foreach ($branchNumber in $branches.Keys) {
            $branch = $branches[$branchNumber]
            $emailGroup = @($branch.Purchasing, $branch.Branch)

            if ($role -ne 'Sales') {
                $emailGroup += @($commonEmails.Availability, $commonEmails.Safety, $branch.Managers)
            }
            
            if ($role -eq 'Branch Manager' -or $role -eq 'Nursery Manager') {
                if ($branch.Security) {
                    $emailGroup += $branch.Security
                }
            }

            $roleGroups[$branchNumber] = $emailGroup
        }

        $groupMapping[$role] = $roleGroups
    }

    do {

        # Gather user information
        $email = Read-Host -Prompt "Enter user's email address"
        $branch = Read-Host -Prompt "Enter user's branch number (42, 43, 44, or 45)"
        $position = Read-Host -Prompt "Enter user's position (Sales, Branch Manager, or Nursery Manager)"
        
        # Check if user wants to set the default password
        $useDefaultPassword = Read-Host -Prompt "Would you like to set the default password (Ch@nge1Me1!)? (Y/N)"
        if ($useDefaultPassword.ToLower() -eq 'y') {
            $newPassword = 'Ch@nge1Me1!'
            Write-Host 'Setting default password...'
            Set-MsolUserPassword -UserPrincipalName $email -NewPassword $newPassword -ForceChangePassword $false
        }
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
            } 
            else {
                Write-Host "User already has the $license license assigned. Skipping."
            }
        }
    Start-Sleep -Seconds 5
    Set-MsolUser -UserPrincipalName $email -BlockCredential $false

        $assignedGroups = $groupMapping[$position][$branch]

        if ($assignedGroups) {
            $allStaffGroup = 'allstaff@mnidirect.com'
            $groupAssigned = $false
            $tries = 0
            $maxTries = 10
    
            # Check if the user is already a member of the allstaff group
            $allStaffGroupMembers = Get-DistributionGroupMember -Identity $allStaffGroup | Select-Object -ExpandProperty PrimarySmtpAddress
            if ($email -in $allStaffGroupMembers) {
                $groupAssigned = $true
                Write-Host "User is already a member of the $allStaffGroup group. Skipping."
            }
    
            # If the user is not a member, attempt to add them to the allstaff group every 60 seconds, up to a maximum of 10 tries
            while (-not $groupAssigned -and $tries -lt $maxTries) {
                $tries++
                try {
                    Add-DistributionGroupMember -Identity $allStaffGroup -Member $email -ErrorAction Stop
                    $groupAssigned = $true
                    Write-Host "User added to the $allStaffGroup group on attempt $tries."
                } 
                catch {
                    Write-Host "Failed to add user to the $allStaffGroup group on attempt $tries. Retrying in 60 seconds..."
                    Start-Sleep -Seconds 60
                }
            }
    
            if (-not $groupAssigned) {
                Write-Host "Failed to add user to the $allStaffGroup group after $maxTries attempts. Please check the user's email address and try again later."
            }
    
            
            foreach ($group in $assignedGroups) {
                $groupMembers = Get-DistributionGroupMember -Identity $group | Select-Object -ExpandProperty PrimarySmtpAddress
                if ($email -notin $groupMembers) {
                    Add-DistributionGroupMember -Identity $group -Member $email
                } 
                else {
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
    } 
    while ($continueOnboarding.ToLower() -eq 'y')
    Write-Host "Onboarding complete."
    Read-Host -Prompt "Press any key to continue..."
    }
#Function to offboard users, but leaves emails and groups set
function OffboardEmployee {

    do {
        # Prompt for user email and new password
        $userEmail = Read-Host -Prompt "Email to be offboarded"
        $newPassword = Read-Host -Prompt "Enter the new password to be set"

        # Prompt for email forwarding address
        $forwardingEmail = Read-Host -Prompt "Enter the email address to forward messages to"

        # Display the username, password, and forwarding email for confirmation
        Write-Host "Please confirm the following information:"
        Write-Host "User email: $userEmail"
        Write-Host "New password: $newPassword"
        Write-Host "Forwarding email: $forwardingEmail"

        # Ask for confirmation before proceeding
        $confirmation = Read-Host -Prompt "To proceed with offboarding, type 'Y'"
        if ($confirmation -eq "Y" -or $confirmation -eq "y") {
            # Block sign-in for the user
            Set-MsolUser -UserPrincipalName $userEmail -BlockCredential $true

            # Reset the user's password
            Write-Host "New user password is:"
            Set-MsolUserPassword -UserPrincipalName $userEmail -NewPassword $newPassword -ForceChangePassword $false

            # Set email forwarding for the user
            Set-Mailbox -Identity $userEmail -ForwardingSmtpAddress $forwardingEmail -DeliverToMailboxAndForward $false

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


#Function to Pull Distribution List function
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

#Function to Pull License List function
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
#Function to show Display Disclaimer
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
    #clears screen
	Clear-Host

    Write-Host -ForegroundColor White $disclaimer
    Write-Host -NoNewline -ForegroundColor White "          Do you agree to the terms? (Y/N): "
    $userAgreement = Read-Host

    return $userAgreement
}
#Function to show a EULA
function EULA{
# Check for user agreement
do {
    $agreement = DisplayDisclaimer
} while ($agreement -notmatch '^[Yy]$')
}
#Define Main function that defines the order of the script functions
function Main {
    SetConsoleAppearance
    CredCheck
    EULA
    UpdateScript

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
}
Main

#NEEDED Function to remove all groups and BB/ BS from user
#NEEDED Function log file with user output of changes
#update function to accept usernames/ assign domain in script
#update onboarding to accept abreviations BM NM SA
#make script able to add a csv of employees without emails in the email groups that should be removed
