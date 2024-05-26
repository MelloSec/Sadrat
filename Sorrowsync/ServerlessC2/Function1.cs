using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using System.IO;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Text;
using System.Linq;
using System.Globalization;
using System.IO.Compression;
using System.Collections.Generic;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;




public static class FileOperationFunctionV2
{
    private static readonly HttpClient httpClient = new HttpClient();
    private static string ghUsername;
    private static string repoName;
    private static string ghToken;
    private static string xHookToken;
    private static string xQueueToken;
    private static string xRegisterToken;
    /*    private static string xorKey;
        private static string xorIV;*/

    static FileOperationFunctionV2()
    {
        InitializeHttpClient();
    }

    private static void InitializeHttpClient()
    {
        string keyVaultUrl = Environment.GetEnvironmentVariable("KeyVaultUrl");
        var secretClient = new SecretClient(new Uri(keyVaultUrl), new DefaultAzureCredential());

        ghUsername = GetSecret(secretClient, "GitHubUsername");
        repoName = GetSecret(secretClient, "GitHubRepoName");
        ghToken = GetSecret(secretClient, "GitHubToken");
        xHookToken = GetSecret(secretClient, "xhooktoken");
        xQueueToken = GetSecret(secretClient, "xqueuetoken");
        xRegisterToken = GetSecret(secretClient, "xregistertoken");
        /*        xorKey = GetSecret(secretClient, "xorKey");
                xorIV = GetSecret(secretClient, "xorIV");*/

        httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("AppName", "1.0"));
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ghToken);
    }

    private static string GetSecret(SecretClient client, string secretName)
    {
        KeyVaultSecret secret = client.GetSecret(secretName);
        return secret.Value;
    }

    /*    private static void InitializeHttpClient()
        {
            ghUsername = Environment.GetEnvironmentVariable("GitHubUsername");
            repoName = Environment.GetEnvironmentVariable("GitHubRepoName");
            ghToken = Environment.GetEnvironmentVariable("GitHubToken");
            xHookToken = Environment.GetEnvironmentVariable("X-HOOK-TOKEN");
            xQueueToken = Environment.GetEnvironmentVariable("X-QUEUE-TOKEN");
            xRegisterToken = Environment.GetEnvironmentVariable("X-REGISTER-TOKEN");
            xorKey = Environment.GetEnvironmentVariable("xorKey");
            xorIV = Environment.GetEnvironmentVariable("xorIV");

            httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("AppName", "1.0"));
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ghToken);
        }*/


    [FunctionName("DeRegisterV2")]
    public static async Task<IActionResult> DeRegister(
    [HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "2.0/deregister/{id}")] HttpRequest req,
    string id,
    ILogger log)
    {
        return await FileOperationFunctionV2.DeRegisterV2(req, id, log);
    }



    [FunctionName("RegisterIDV2")]
    public static async Task<IActionResult> RegisterIDV2(
    [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "2.0/registration/{id}")] HttpRequest req,
    string id, ILogger log)
    {
        try
        {
            log.LogInformation($"RegisterIDV2 function triggered for ID: {id}");
            /*
                        // Check for X-HOOK-TOKEN, X-REGISTER-TOKEN, and X-QUEUE-TOKEN headers
                        if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var receivedHookToken) ||
                            !req.Headers.TryGetValue("X-REGISTER-TOKEN", out var receivedRegisterToken))
                        {
                            log.LogError("Missing one or more required headers: X-HOOK-TOKEN, X-REGISTER-TOKEN.");
                            return new UnauthorizedResult(); // Missing one or more headers
                        }

                        // Validate the tokens
                        if (receivedHookToken != xHookToken || receivedRegisterToken != xRegisterToken)
                        {
                            log.LogError("Invalid or missing headers: X-HOOK-TOKEN, X-REGISTER-TOKEN.");
                            return new UnauthorizedResult(); // Invalid or missing tokens
                        }*/


            string agentsFilePath = "agents.txt";

            // Use the internal apiListIDs method to get the content of "agents.txt"
            string agentsFileContent = await apiListAgents(log);

            // Create "agents.txt" if it doesn't exist
            if (string.IsNullOrEmpty(agentsFileContent))
            {
                log.LogInformation("Creating 'agents.txt' file.");
                await CreateAgentsFile(id); // Change to your method that creates the file
            }


            // Check if the ID is already registered in "agents.txt"

            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{agentsFilePath}";
            HttpResponseMessage agentsResponse = await httpClient.GetAsync(githubUrl);



            /*   string agentRegistration = $"{id}:{GetClientIPAddress(req)}";*/

            string idstr = id.ToString();
            string agentRegistration = idstr;

            try
            {
                if (agentsFileContent.Contains(agentRegistration))
                {
                    log.LogInformation($"Agent with ID {id} is already registered.");
                    return new BadRequestObjectResult("Agent is already registered.");
                }
            }
            catch (Exception ex)
            {
                log.LogError($"An error occurred while checking agent registration: {ex.Message}");
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }


            try
            {
                // Proceed with agent registration
                // Write a timestamp into "{id}/age.txt" in that folder
                string ageFilePath = $"{id}/age.txt";
                await WriteAgeFile(ageFilePath, log);

                // added create checkin to read script into checkin 
                await CreateCheckinFile(id, log);
            }
            catch (Exception ex)
            {
                log.LogError($"An error occurred while writing the age file: {ex.Message}");
                // Handle the exception or rethrow it if necessary
            }


            // Update the "agents.txt" file
            string remoteIp = req.Headers["X-Forwarded-For"];
            if (string.IsNullOrEmpty(remoteIp))
            {
                remoteIp = req.HttpContext.Connection.RemoteIpAddress.ToString();
            }
            string idWithRemoteIp = $"{id}:{remoteIp}";


            await AppendIDToFile(agentsFilePath, idWithRemoteIp, log);

            // Return a success response
            log.LogInformation($"Agent with ID {id} and IP {GetClientIPAddress(req)} has been successfully registered.");
            return new OkObjectResult($"Agent with ID {id} has been successfully registered.");
        }
        catch (Exception ex)
        {
            log.LogError($"An error occurred in RegisterIDV2 function: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }

    [FunctionName("RegisterID")]
    public static async Task<IActionResult> RegisterID(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "2.0/register/{id}")] HttpRequest req,
        string id, ILogger log)
    {
        try
        {
            log.LogInformation($"RegisterID function triggered for ID: {id}");

            // Check for X-HOOK-TOKEN, X-REGISTER-TOKEN, and X-QUEUE-TOKEN headers
            // Check for X-HOOK-TOKEN and X-REGISTER-TOKEN headers
            if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var receivedHookToken) ||
                !req.Headers.TryGetValue("X-REGISTER-TOKEN", out var receivedRegisterToken))
            {
                log.LogError("Missing one or more required headers: X-HOOK-TOKEN, X-REGISTER-TOKEN.");
                return new UnauthorizedResult(); // Missing one or more headers
            }

            // Validate the tokens
            if (receivedHookToken != xHookToken || receivedRegisterToken != xRegisterToken)
            {
                log.LogError("Invalid or missing headers: X-HOOK-TOKEN, X-REGISTER-TOKEN.");
                return new UnauthorizedResult(); // Invalid or missing tokens
            }



            // Check if the ID is already registered
            string idsFilePath = "IDs.txt";
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{idsFilePath}";
            HttpResponseMessage idsResponse = await httpClient.GetAsync(githubUrl);

            // Use the internal apiListIDs method to get the content of IDs.txt
            string idsFileContent = await apiListIDs(log);
            if (string.IsNullOrEmpty(idsFileContent))
            {
                return new BadRequestObjectResult("Unable to retrieve registered IDs.");
            }

            if (idsFileContent.Contains(id))
            {
                log.LogInformation($"ID {id} is already registered.");
                return new BadRequestObjectResult("ID is already registered.");
            }

            bool idsFileExists = false;

            // Proceed with registration if ID is not found in IDs.txt
            // Write a timestamp into "age.txt" in that folder
            string ageFilePath = $"{id}/age.txt";
            await WriteAgeFile(ageFilePath, log);

            // Update the IDs.txt file
            if (!idsFileExists)
            {
                log.LogInformation("IDs.txt file does not exist. Creating the file.");
                await CreateIDFile(id);
            }
            else
            {
                // Append the new ID to the existing IDs.txt file
                await AppendIDToFile(idsFilePath, id, log);
            }

            await AppendIDToFile(idsFilePath, id, log);

            // Return a success response
            log.LogInformation($"ID {id} has been successfully registered.");
            return new OkObjectResult($"ID {id} has been successfully registered.");
        }
        catch (Exception ex)
        {
            log.LogError($"An error occurred in RegisterID function: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }

    [FunctionName("AppendTaskV2")]
    public static async Task<IActionResult> AppendTaskV2(
    [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "2.0/tasker/{id}")] HttpRequest req,
    string id, ILogger log)
    {
        try
        {
            // Extract command data from the request body once.
            string commandData = await new StreamReader(req.Body).ReadToEndAsync();

            log.LogInformation($"Received command for {id}: '{commandData}'");

            // Construct the URL to access the checkin.txt file within the specified directory (id).
            string completeUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{id}/checkin.txt";

            // Fetch the current file SHA, assuming httpClient is already initialized and configured
            var shaResponse = await httpClient.GetAsync(completeUrl);
            string sha = null;
            string existingContent = "";

            if (shaResponse.IsSuccessStatusCode)
            {
                var shaContent = await shaResponse.Content.ReadAsStringAsync();
                dynamic shaObject = JsonConvert.DeserializeObject(shaContent);
                sha = shaObject.sha;

                // Decode existing content if the file exists and SHA is not null
                string encodedContent = shaObject.content;
                if (!string.IsNullOrEmpty(encodedContent))
                {
                    byte[] decodedBytes = Convert.FromBase64String(encodedContent);
                    existingContent = Encoding.UTF8.GetString(decodedBytes);
                }
            }

            // Appending the new content to the existing content
            string updatedContent = $"{existingContent}\n{commandData}";

            byte[] updatedBytes = Encoding.UTF8.GetBytes(updatedContent);
            string base64UpdatedContent = Convert.ToBase64String(updatedBytes);

            // Create the update payload with the SHA included only if it's available
            var updatePayload = new
            {
                message = $"Append new task to checkin for {id}",
                content = base64UpdatedContent,
                sha = sha
            };

            var updateContent = new StringContent(JsonConvert.SerializeObject(updatePayload), Encoding.UTF8, "application/json");

            // Send the update request
            HttpResponseMessage updateResponse = await httpClient.PutAsync(completeUrl, updateContent);
            if (!updateResponse.IsSuccessStatusCode)
            {
                log.LogError($"Failed to append task. Status code: {updateResponse.StatusCode}. URL: {completeUrl}");
                return new StatusCodeResult((int)updateResponse.StatusCode);
            }

            log.LogInformation($"Task appended successfully to: {completeUrl}");
            return new OkObjectResult(new { Message = "Task appended successfully." });
        }
        catch (Exception ex)
        {
            log.LogError($"Error in AppendTaskV2: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }


    [FunctionName("ListModuleLogs")]
    public static async Task<IActionResult> ListModuleLogs(
    [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "2.0/logs/{filename}")] HttpRequest req,
    string filename, // Dynamically capture the filename from the route
    ILogger log)
    {
        try
        {
            // Retrieve the X-HOOK-TOKEN header from the request
            if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var receivedHookToken))
            {
                log.LogError("Missing X-HOOK-TOKEN header.");
                return new UnauthorizedResult(); // Missing X-HOOK-TOKEN header
            }

            // Validate the X-HOOK-TOKEN
            if (receivedHookToken != xHookToken)
            {
                log.LogError("Invalid X-HOOK-TOKEN header.");
                return new UnauthorizedResult(); // Invalid X-HOOK-TOKEN
            }

            // Construct the GitHub URL with the dynamic filename
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{filename}";

            httpClient.DefaultRequestHeaders.UserAgent.TryParseAdd("request");

            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                var contentObject = JsonConvert.DeserializeObject<dynamic>(jsonResponse);

                if (contentObject != null && contentObject.content != null)
                {
                    byte[] data = Convert.FromBase64String(contentObject.content.ToString());
                    string logFileContent = Encoding.UTF8.GetString(data);

                    string[] lines = logFileContent.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    int startIdx = Math.Max(0, lines.Length - 100);
                    string last50Lines = string.Join("\n", lines.Skip(startIdx));

                    return new OkObjectResult(last50Lines);
                }
                else
                {
                    log.LogInformation($"{filename} file is empty or does not exist.");
                    return new NoContentResult();
                }
            }
            else
            {
                log.LogError($"Failed to retrieve {filename} file. Status: {response.StatusCode}");
                return new StatusCodeResult((int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in ListModuleLogs: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }



    [FunctionName("ListLogEvents")]
    public static async Task<IActionResult> ListLogEvents(
    [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "2.0/syslog/check")] HttpRequest req,
    ILogger log)
    {
        try
        {
            // Retrieve the X-HOOK-TOKEN header from the request
            if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var receivedHookToken))
            {
                log.LogError("Missing X-HOOK-TOKEN header.");
                return new UnauthorizedResult(); // Missing X-HOOK-TOKEN header
            }

            // Validate the X-HOOK-TOKEN
            string expectedHookToken = xHookToken;

            if (receivedHookToken != expectedHookToken)
            {
                log.LogError("Invalid X-HOOK-TOKEN header.");
                return new UnauthorizedResult(); // Invalid X-HOOK-TOKEN
            }

            // Your code logic here if the X-HOOK-TOKEN is valid
            string logFilePath = "log.txt"; // Update to log.txt
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{logFilePath}";

            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                var contentObject = JsonConvert.DeserializeObject<dynamic>(jsonResponse);

                if (contentObject != null && contentObject.content != null)
                {
                    byte[] data = Convert.FromBase64String(contentObject.content.ToString());
                    string logFileContent = Encoding.UTF8.GetString(data);

                    // Split the content into lines
                    string[] lines = logFileContent.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);

                    // Get the last 50 lines or fewer if there are less than 50 lines
                    int startIdx = Math.Max(0, lines.Length - 50);
                    string last50Lines = string.Join("\n", lines.Skip(startIdx));

                    return new OkObjectResult(last50Lines);
                }
                else
                {
                    log.LogInformation("log.txt file is empty or does not exist.");
                    return new NoContentResult();
                }
            }
            else
            {
                log.LogError($"Failed to retrieve log.txt file. Status: {response.StatusCode}");
                return new StatusCodeResult((int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in ListLogEvents: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }


    [FunctionName("ListAgentsV2")]
    public static async Task<IActionResult> ListAgentsV2(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "2.0/listagents")] HttpRequest req,
        ILogger log)
    {
        try
        {
            log.LogInformation("ListAgents function triggered.");

            /*            if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var receivedHookToken) ||
                            !req.Headers.TryGetValue("X-QUEUE-TOKEN", out var receivedQueueToken))
                        {
                            log.LogError("Missing one or more required headers: X-HOOK-TOKEN, X-QUEUE-TOKEN.");
                            return new UnauthorizedResult(); // Missing one or more headers
                        }

                        if (receivedHookToken != xHookToken || receivedQueueToken != xQueueToken)
                        {
                            log.LogError("Invalid or missing headers: X-HOOK-TOKEN, X-QUEUE-TOKEN.");
                            return new UnauthorizedResult(); // Invalid or missing tokens
                        }
            */
            string agentsFilePath = "agents.txt";
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{agentsFilePath}";

            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                var contentObject = JsonConvert.DeserializeObject<dynamic>(jsonResponse);

                if (contentObject != null && contentObject.content != null)
                {
                    byte[] data = Convert.FromBase64String(contentObject.content.ToString());
                    string agentsFileContent = Encoding.UTF8.GetString(data);

                    return new OkObjectResult(agentsFileContent);
                }
                else
                {
                    log.LogInformation("agents file is empty or does not exist.");
                    return new NoContentResult();
                }
            }
            else
            {
                log.LogError($"Failed to retrieve agents.json file. Status: {response.StatusCode}");
                return new StatusCodeResult((int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in ListAgents: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }

    [FunctionName("ListIDs")]
    public static async Task<IActionResult> ListIDs(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "2.0/listids")] HttpRequest req,
            ILogger log)
    {
        try
        {


            // Assuming the necessary header checks are performed here
            if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var receivedHookToken) ||
            !req.Headers.TryGetValue("X-QUEUE-TOKEN", out var receivedQueueToken))
            {
                log.LogError("Missing one or more required headers: X-HOOK-TOKEN, X-QUEUE-TOKEN.");
                return new UnauthorizedResult(); // Missing one or more headers
            }

            // Validate the tokens
            if (receivedHookToken != xHookToken || receivedQueueToken != xQueueToken)
            {
                log.LogError("Invalid or missing headers: X-HOOK-TOKEN, X-QUEUE-TOKEN.");
                return new UnauthorizedResult(); // Invalid or missing tokens
            }

            // Retrieve the X-HOOK-TOKEN header from the request

            string idsFilePath = "IDs.txt";
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{idsFilePath}";

            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                var contentObject = JsonConvert.DeserializeObject<dynamic>(jsonResponse);

                if (contentObject != null && contentObject.content != null)
                {
                    byte[] data = Convert.FromBase64String(contentObject.content.ToString());
                    string idsFileContent = Encoding.UTF8.GetString(data);

                    return new OkObjectResult(idsFileContent);
                }
                else
                {
                    log.LogInformation("IDs.txt file is empty or does not exist.");
                    return new NoContentResult();
                }
            }
            else
            {
                log.LogError($"Failed to retrieve IDs.txt file. Status: {response.StatusCode}");
                return new StatusCodeResult((int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in ListIDs: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }



    [FunctionName("FileOperationV2")]
    public static async Task<IActionResult> RunFileOperationV2(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = "2.0/{operation}/{id}/{fileType}")] HttpRequest req,
        string operation, string id, string fileType, ExecutionContext context, ILogger log)
    {
        try
        {
            /*
                        var blocklistMiddleware = new BlocklistMiddleware(log); // You can pass null here or create a custom delegate if needed

                        if (blocklistMiddleware.IsBlocked(id))
                        {
                            log.LogInformation($"Agent ID {id} is blocked.");
                            return new StatusCodeResult(403); // Forbidden
                        }*/

            // Header check for X-HOOK-TOKEN
            if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var hookToken) || hookToken != xHookToken)
            {
                return new EmptyResult();
            }

            string fileName = $"{id}/{fileType}.txt";
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";

            switch (operation.ToLower())
            {
                case "rootread":
                    var rootreadResult = await ReadFromFile(githubUrl, log);
                    await AppendToLog($"[{DateTime.UtcNow}] Read operation on file: {fileName} for ID: {id}");
                    return rootreadResult;

                case "read":
                    var readResult = await ReadFromAgentFile(id, fileType, log);
                    await AppendToLog($"[{DateTime.UtcNow}] Read operation on agent file: {id}/{fileType} for ID: {id}");
                    return readResult;

                case "taskresult":
                    log.LogInformation("Task Result operation triggered.");
                    // Replace with agent-specific secret here, for now just the X Hook
                    /*                        if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var headerHookToken) || headerHookToken != xHookToken)
                                            {
                                                log.LogWarning("Invalid or missing X-HOOK-TOKEN header.");
                                                return new UnauthorizedResult(); // Invalid or missing X-HOOK-TOKEN header
                                            }*/
                    /* log.LogInformation($"Valid X-HOOK-TOKEN header: {headerHookToken}");*/
                    await AppendToLog($"[{DateTime.UtcNow}] Task Result write operation on file: {fileName} for ID: {id}");
                    return await WriteResult(id, await new StreamReader(req.Body).ReadToEndAsync(), log);
                /*return await WriteAgentResults(id, await new StreamReader(req.Body).ReadToEndAsync(), log);*/

                case "taskwrite":
                    log.LogInformation("Task Write operation triggered.");
                    // Other code for headers and validation...

                    // Pass only the ID to AppendCheckinV2
                    var taskWriteResult = await AppendCheckinV2(githubUrl, id, req, log);
                    await AppendToLog($"[{DateTime.UtcNow}] Task write operation for ID: {id}");
                    return taskWriteResult;

                case "write":
                    // Prevent writing to checkin files without X-QUEUE-TOKEN
                    if (fileType.Equals("checkin", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!req.Headers.TryGetValue("X-QUEUE-TOKEN", out var receivedQueueToken) || receivedQueueToken != xQueueToken)
                        {
                            log.LogError("Invalid or missing X-QUEUE-TOKEN header for checkin file type.");
                            return new UnauthorizedResult(); // Invalid or missing X-QUEUE-TOKEN
                        }
                    }
                    var writeResult = await AppendToFile(githubUrl, fileName, req, log);
                    await AppendToLog($"[{DateTime.UtcNow}] Write operation on file: {fileName} for ID: {id}");
                    return writeResult;

                case "task":
                    var taskResult = await ReadAndRemoveCommandFromFileV2(id, log);
                    await AppendToLog($"[{DateTime.UtcNow}] Read and remove command operation for ID: {id}");
                    return new OkObjectResult(taskResult);

                default:
                    return new BadRequestObjectResult("Invalid operation.");
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in FileOperationV2: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }

    // Routes

    [FunctionName("AgentDownload")]
    public static async Task<IActionResult> AgentDownload(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "2.0/agentdownload/{id}/{filename}")] HttpRequest req,
        string id, string filename, ExecutionContext context, ILogger log)
    {
        try
        {
            if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var hookToken) || hookToken != xHookToken)
            {
                return new UnauthorizedResult();
            }

            InitializeHttpClient(); // Ensure HttpClient is initialized

            string targetFilePath = $"{id}/{filename}";
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{targetFilePath}";
            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                var fileContentResponse = await response.Content.ReadAsStringAsync();
                var fileContentObject = JObject.Parse(fileContentResponse);
                string base64Content = fileContentObject["content"].ToString();
                byte[] data = Convert.FromBase64String(base64Content);
                return new FileContentResult(data, "application/octet-stream")
                {
                    FileDownloadName = filename
                };
            }
            else
            {
                log.LogError($"Failed to download file from {targetFilePath}. Status: {response.StatusCode}");
                return new StatusCodeResult((int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in AgentDownload: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }



    [FunctionName("Download")]
    public static async Task<IActionResult> Download(
    [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "2.0/download/{filename}")] HttpRequest req,
    string filename, ExecutionContext context, ILogger log)
    {
        try
        {
            if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var hookToken) || hookToken != xHookToken)
            {
                return new UnauthorizedResult();
            }

            InitializeHttpClient(); 

            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{filename}";
            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                var fileContentResponse = await response.Content.ReadAsStringAsync();
                var fileContentObject = JObject.Parse(fileContentResponse);
                string base64Content = fileContentObject["content"].ToString();
                byte[] data = Convert.FromBase64String(base64Content);
                return new FileContentResult(data, "application/octet-stream")
                {
                    FileDownloadName = filename
                };
            }
            else
            {
                log.LogError($"Failed to download file. Status: {response.StatusCode}");
                return new StatusCodeResult((int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in Download: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }


    [FunctionName("AgentUpload")]
    public static async Task<IActionResult> AgentUpload(
    [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "2.0/agentupload/{id}/{filename}")] HttpRequest req,
    string id, string filename, ExecutionContext context, ILogger log)
    {
        try
        {
            if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var hookToken) || hookToken != xHookToken)
            {
                return new UnauthorizedResult();
            }

            InitializeHttpClient(); // Initialize HttpClient

            // Read the data from the request body
            string data = await new StreamReader(req.Body).ReadToEndAsync();

            // Specify the destination file name and path in the GitHub repository
            string targetFilePath = $"{id}/{filename}";
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{targetFilePath}";

            // Upload the data to the specified file in the GitHub repository
            await UploadFileContent(githubUrl, data);

            // Log the successful upload
            log.LogInformation($"Data uploaded successfully to {targetFilePath}");

            return new OkObjectResult($"Data uploaded successfully to {targetFilePath}");
        }
        catch (Exception ex)
        {
            log.LogError($"Error in AgentUpload: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }


    [FunctionName("Upload")]
    public static async Task<IActionResult> Upload(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "2.0/upload/{filename}")] HttpRequest req,
        string filename, ExecutionContext context, ILogger log)
    {
        try
        {
            if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var hookToken) || hookToken != xHookToken)
            {
                return new EmptyResult();
            }

            InitializeHttpClient(); // Initialize HttpClient

            // Read the data from the request body
            string data = await new StreamReader(req.Body).ReadToEndAsync();

            // Specify the destination file name and path in the GitHub repository
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{filename}";

            // Upload the data to the specified file in the GitHub repository
            await UploadFileContent(githubUrl, data);

            // Log the successful upload
            log.LogInformation($"Data uploaded successfully to {filename}");

            return new OkObjectResult($"Data uploaded successfully to {filename}");
        }
        catch (Exception ex)
        {
            log.LogError($"Error in Upload: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }



    [FunctionName("ListAgentFiles")]
    public static async Task<IActionResult> ListAgentFiles(
        [HttpTrigger(AuthorizationLevel.Function, "get", Route = "2.0/list/{id}")] HttpRequest req,
        string id, ILogger log)
    {
        try
        {
            if (!req.Headers.TryGetValue("X-HOOK-TOKEN", out var hookToken) || hookToken != xHookToken)
            {
                log.LogWarning("Unauthorized access attempt to ListAgentFiles.");
                return new UnauthorizedResult(); // Changed from EmptyResult to explicitly indicate unauthorized access
            }

            string folderPath = $"{id}";
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{folderPath}";
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("request"); // Example user agent, adjust as needed


            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                var files = JArray.Parse(content);
                var fileNames = files.Select(file => file["name"].ToString()).ToList();

                return new OkObjectResult(fileNames);
            }
            else
            {
                log.LogError($"GitHub API call failed: {response.StatusCode}");
                return new StatusCodeResult((int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in ListAgentFiles: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }

    // Operations
    private static async Task UploadFileContent(string githubUrl, string content)
    {
        try
        {


            // Create the update payload
            var updatePayload = new
            {
                message = "Upload file content",
                content = Convert.ToBase64String(Encoding.UTF8.GetBytes(content))
            };

            var updateContent = new StringContent(JsonConvert.SerializeObject(updatePayload), Encoding.UTF8, "application/json");

            // Send the update request to GitHub
            HttpResponseMessage updateResponse = await httpClient.PutAsync(githubUrl, updateContent);

            if (!updateResponse.IsSuccessStatusCode)
            {
                throw new Exception($"Failed to upload file content: {updateResponse.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            // Handle any exceptions that occur during the upload
            throw new Exception($"Error in UploadFileContent: {ex.Message}");
        }
    }

    private static async Task<string> DownloadFileContent(string githubUrl, string githubApiToken, ILogger log)
    {
        using (var httpClient = new HttpClient())
        {
            /*httpClient.DefaultRequestHeaders.Add("Authorization", $"{githubApiToken}");*/

            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                string jsonContent = await response.Content.ReadAsStringAsync();
                dynamic githubResponse = JsonConvert.DeserializeObject(jsonContent);

                // Ensure that the GitHub API response contains the 'content' field.
                if (githubResponse != null && githubResponse.content != null)
                {
                    string base64Content = githubResponse.content;
                    return base64Content;
                }
                else
                {
                    log.LogError("GitHub API response does not contain 'content' field.");
                    throw new Exception("GitHub API response is missing 'content' field.");
                }
            }
            else
            {
                log.LogError($"Failed to fetch file content from GitHub. Status code: {response.StatusCode}");
                throw new Exception($"Failed to fetch file content from GitHub. Status code: {response.StatusCode}");
            }
        }
    }


    private static async Task<string> DownloadFileContent(string githubUrl, ILogger log)
    {
        using (var httpClient = new HttpClient())
        {
            // Set headers as needed (e.g., authentication headers)
            // Add any necessary headers for authentication to the GitHub API
            // httpClient.DefaultRequestHeaders.Add("Authorization", "Bearer YourToken");

            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                string jsonContent = await response.Content.ReadAsStringAsync();
                dynamic githubResponse = JsonConvert.DeserializeObject(jsonContent);

                // Ensure that the GitHub API response contains the 'content' field.
                if (githubResponse != null && githubResponse.content != null)
                {
                    string base64Content = githubResponse.content;
                    return base64Content;
                }
                else
                {
                    log.LogError("GitHub API response does not contain 'content' field.");
                    throw new Exception("GitHub API response is missing 'content' field.");
                }
            }
            else
            {
                log.LogError($"Failed to fetch file content from GitHub. Status code: {response.StatusCode}");
                throw new Exception($"Failed to fetch file content from GitHub. Status code: {response.StatusCode}");
            }
        }
    }





    // Implementations for ReadFromFile, AppendToFile, ReadAndRemoveCommand, AppendToLog
    // Helper method to get the client IP address from the request
    private static string GetClientIPAddress(HttpRequest request)
    {
        string ipAddress = request.HttpContext.Connection.RemoteIpAddress?.ToString();
        return ipAddress;
    }
    private static async Task AppendAgentToFile(string id, ILogger log)
    {
        try
        {
            // Define the GitHub API URL for checking if the file exists
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/agents.txt";

            // Send a GET request to check if the file exists
            var response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                // File exists, retrieve its current content
                string existingContent = await response.Content.ReadAsStringAsync();

                // Retrieve the SHA from the response headers
                string sha = response.Headers.ETag?.Tag;

                // Check if the agent ID is already present in the content
                string agentRegistration = $"{id}\n";
                if (existingContent.Contains(agentRegistration))
                {
                    log.LogInformation($"Agent with ID {id} is already registered.");
                    return;
                }

                // Append the new agent information with a new line
                string updatedContentWithNewLine = existingContent + agentRegistration;

                // Delete the existing file
                await DeleteAgentsFile(sha, log);

                // Create a JSON payload with the updated content
                string payload = $"{{ \"message\": \"Updated agents.txt\", \"content\": \"{Convert.ToBase64String(Encoding.UTF8.GetBytes(updatedContentWithNewLine))}\" }}";

                // Make a PUT request to create a new file
                response = await httpClient.PutAsync(githubUrl, new StringContent(payload, Encoding.UTF8, "application/json"));

                if (!response.IsSuccessStatusCode)
                {
                    log.LogError($"Failed to update agents.txt. Status code: {response.StatusCode}");
                    throw new Exception($"Failed to update agents.txt");
                }

                log.LogInformation($"Agent ID {id} has been successfully appended to agents.txt.");
            }
            else
            {
                // File does not exist, create a new file
                await CreateAgentsFile(id); // Implement this method to create the file
                log.LogInformation($"Created 'agents.txt' file with agent ID {id}.");
            }
        }
        catch (Exception ex)
        {
            log.LogError($"An error occurred while appending the agent ID to agents.txt: {ex.Message}");
            throw;
        }
    }

    private static async Task DeleteAgentsFile(string sha, ILogger log)
    {
        try
        {
            if (string.IsNullOrEmpty(sha))
            {
                log.LogWarning("SHA is missing, cannot delete agents.txt.");
                return;
            }

            // Define the GitHub API URL for deleting the file
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/agents.txt";

            // Create a JSON payload for deleting the file
            string payload = $"{{ \"message\": \"Delete agents.txt\", \"sha\": \"{sha}\" }}";

            // Make a DELETE request to delete the file
            var response = await httpClient.DeleteAsync(githubUrl); // Pass null as the second argument

            if (!response.IsSuccessStatusCode)
            {
                log.LogError($"Failed to delete agents.txt. Status code: {response.StatusCode}");
                throw new Exception($"Failed to delete agents.txt");
            }

            log.LogInformation("agents.txt file has been successfully deleted.");
        }
        catch (Exception ex)
        {
            log.LogError($"An error occurred while deleting agents.txt: {ex.Message}");
            throw;
        }
    }


    public static async Task<IActionResult> DeRegisterV2(HttpRequest req, string id, ILogger log)
    {
        try
        {
            // Read the contents of agents.txt
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/agents.txt";
            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (!response.IsSuccessStatusCode)
            {
                log.LogError($"Failed to read agents.txt. Status code: {response.StatusCode}");
                throw new Exception($"Failed to read agents.txt");
            }
            string existingContent = await response.Content.ReadAsStringAsync();

            // Log the existingContent for debugging
            log.LogInformation($"Existing Content in agents.txt: {existingContent}");

            // Extract the agent ID and IP from the id parameter
            string[] idParts = id.Split(':');
            if (idParts.Length != 2)
            {
                log.LogError("Invalid id format. Use 'ID:IP' format.");
                return new BadRequestObjectResult("Invalid id format.");
            }

            string agentIdToDeregister = idParts[0] + ":" + idParts[1];

            // Log the agentIdToDeregister for debugging
            log.LogInformation($"Agent ID to Deregister: {agentIdToDeregister}");

            // Check if the agent ID and IP are present in the file
            if (!existingContent.Contains(agentIdToDeregister))
            {
                log.LogInformation($"Agent with ID {agentIdToDeregister} is not registered.");
                return new OkResult();
            }

            // Remove the agent ID and IP from the content
            string updatedContent = existingContent.Replace(agentIdToDeregister, string.Empty);

            // Create a JSON payload with the updated content and SHA
            string sha = response.Headers.ETag?.Tag;
            string payload = $"{{ \"message\": \"Updating agents.txt (Deregister) for {agentIdToDeregister}\", \"content\": \"{Convert.ToBase64String(Encoding.UTF8.GetBytes(updatedContent))}\", \"sha\": \"{sha}\" }}";

            // Make a PUT request to update the file and remove the agent ID and IP
            response = await httpClient.PutAsync(githubUrl, new StringContent(payload, Encoding.UTF8, "application/json"));

            if (!response.IsSuccessStatusCode)
            {
                log.LogError($"Failed to update agents.txt. Status code: {response.StatusCode}");
                throw new Exception($"Failed to update agents.txt");
            }

            log.LogInformation($"Agent ID {agentIdToDeregister} has been successfully deregistered.");

            // Optionally, you can delete the agent's folder here if needed.
            // Successfully deregistered agent from agents.txt, now delete the agent's folder
            string agentFolderUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{agentIdToDeregister}";
            string folderPayload = $"{{ \"message\": \"Deleting folder for agent {agentIdToDeregister}\", \"sha\": \"\" }}"; // Set sha to an empty string

            response = await httpClient.DeleteAsync(agentFolderUrl);

            if (!response.IsSuccessStatusCode)
            {
                log.LogError($"Failed to delete agent's folder. Status code: {response.StatusCode}");
                throw new Exception($"Failed to delete agent's folder.");
            }

            log.LogInformation($"Agent's folder for {agentIdToDeregister} has been successfully deleted.");




            return new OkResult();
        }
        catch (Exception ex)
        {
            log.LogError($"An error occurred while deregistering agent ID {id}: {ex.Message}");
            return new StatusCodeResult(500);
        }
    }

    private static async Task<bool> FileExists(string fileName)
    {
        string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ghToken);

        HttpResponseMessage response = await httpClient.GetAsync(githubUrl);
        return response.IsSuccessStatusCode;
    }

    private static async Task DeleteFile(string fileName)
    {
        string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ghToken);

        // First, get the file SHA
        HttpResponseMessage shaResponse = await httpClient.GetAsync(githubUrl);
        if (!shaResponse.IsSuccessStatusCode)
        {
            throw new Exception("Failed to get file SHA for deletion.");
        }

        var shaContent = await shaResponse.Content.ReadAsStringAsync();
        var shaObject = JObject.Parse(shaContent);
        var sha = shaObject["sha"]?.ToString();

        // Then, delete the file using the SHA
        var deletePayload = new
        {
            message = $"Delete {fileName}",
            sha = sha
        };
        var deleteContent = new StringContent(JsonConvert.SerializeObject(deletePayload), Encoding.UTF8, "application/json");

        // Constructing HttpRequestMessage for DELETE
        var requestMessage = new HttpRequestMessage
        {
            Method = HttpMethod.Delete,
            RequestUri = new Uri(githubUrl),
            Content = deleteContent
        };

        // Perform the delete operation
        HttpResponseMessage deleteResponse = await httpClient.SendAsync(requestMessage);

        if (!deleteResponse.IsSuccessStatusCode)
        {
            throw new Exception($"Failed to delete file: {deleteResponse.StatusCode}");
        }
    }

    private static async Task AppendIDToFile(string idsFilePath, string id, ILogger log)
    {
        string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{idsFilePath}";
        HttpResponseMessage getResponse = await httpClient.GetAsync(githubUrl);

        string idsFileContent = "";
        string sha = null; // SHA of the existing file, required for updating

        // Check if the IDs.txt file exists and read its content
        if (getResponse.IsSuccessStatusCode)
        {
            var getFileResponse = await getResponse.Content.ReadAsStringAsync();
            var fileContentObject = JsonConvert.DeserializeObject<dynamic>(getFileResponse);

            if (fileContentObject != null && fileContentObject.content != null)
            {
                byte[] data = Convert.FromBase64String(fileContentObject.content.ToString());
                idsFileContent = Encoding.UTF8.GetString(data);
                sha = fileContentObject.sha;
            }
        }

        // Append the new ID to the content
        idsFileContent += $"\n{id}";

        // Encode the updated content to Base64
        var updatedContentBytes = Encoding.UTF8.GetBytes(idsFileContent);
        var updatedContentBase64 = Convert.ToBase64String(updatedContentBytes);

        // Create the update request content
        var updateRequest = new
        {
            message = $"Append new ID: {id}",
            committer = new { name = "Your Name", email = "your-email@example.com" },
            content = updatedContentBase64,
            sha = sha
        };

        var updateRequestJson = new StringContent(JsonConvert.SerializeObject(updateRequest), Encoding.UTF8, "application/json");

        // Send the update request to GitHub
        HttpResponseMessage updateResponse = await httpClient.PutAsync(githubUrl, updateRequestJson);

        if (!updateResponse.IsSuccessStatusCode)
        {
            log.LogError($"Failed to update IDs.txt file. Status: {updateResponse.StatusCode}");
            throw new Exception("Failed to update IDs.txt file.");
        }
    }


    private static async Task AppendToLog(string message)
    {
        string fileName = "log.txt";
        string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";

        // Get current content and SHA of log file
        var shaResponse = await httpClient.GetAsync(githubUrl);
        string existingContent = "";
        string sha = null;

        if (shaResponse.IsSuccessStatusCode)
        {
            var shaContent = await shaResponse.Content.ReadAsStringAsync();
            var shaObject = JObject.Parse(shaContent);
            sha = shaObject["sha"]?.ToString();

            // Decode existing content if file exists
            string encodedContent = shaObject["content"]?.ToString();
            if (!string.IsNullOrEmpty(encodedContent))
            {
                byte[] decodedBytes = Convert.FromBase64String(encodedContent);
                existingContent = Encoding.UTF8.GetString(decodedBytes);
            }
        }

        // Append new message
        string updatedContent = string.IsNullOrEmpty(existingContent) ? message : $"{existingContent}\n{message}";
        byte[] updatedBytes = Encoding.UTF8.GetBytes(updatedContent);
        string base64UpdatedContent = Convert.ToBase64String(updatedBytes);

        // Update or create the log file
        var updatePayload = new
        {
            message = $"Update {fileName}",
            content = base64UpdatedContent,
            sha = sha
        };
        var updateContent = new StringContent(JsonConvert.SerializeObject(updatePayload), Encoding.UTF8, "application/json");

        await httpClient.PutAsync(githubUrl, updateContent);
    }


    private static async Task CreateAgentsFile(string id)
    {
        string fileName = "agents.txt";
        string content = $"{id}\n"; // Prepare the content with the ID to be added

        string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ghToken);

        var updatePayload = new
        {
            message = $"Create {fileName}",
            content = Convert.ToBase64String(Encoding.UTF8.GetBytes(content))
        };

        var updateContent = new StringContent(JsonConvert.SerializeObject(updatePayload), Encoding.UTF8, "application/json");

        await httpClient.PutAsync(githubUrl, updateContent);
    }


    private static async Task CreateIDFile(string id)
    {
        string fileName = "IDs.txt";
        string content = $"{id}\n"; // Prepare the content with the ID to be added

        string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ghToken);

        var updatePayload = new
        {
            message = $"Create {fileName}",
            content = Convert.ToBase64String(Encoding.UTF8.GetBytes(content))
        };

        var updateContent = new StringContent(JsonConvert.SerializeObject(updatePayload), Encoding.UTF8, "application/json");

        await httpClient.PutAsync(githubUrl, updateContent);
    }

    private static async Task<string> apiListAgents(ILogger log)
    {
        try
        {
            string idsFilePath = "agents.txt";
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{idsFilePath}";

            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                var contentObject = JsonConvert.DeserializeObject<dynamic>(jsonResponse);

                if (contentObject != null && contentObject.content != null)
                {
                    byte[] data = Convert.FromBase64String(contentObject.content.ToString());
                    return Encoding.UTF8.GetString(data);
                }
                else
                {
                    log.LogInformation("agents.txt file is empty or does not exist.");
                    return null; // Or an appropriate response
                }
            }
            else
            {
                log.LogError($"Failed to retrieve agents.txt file. Status: {response.StatusCode}");
                return null; // Or an appropriate response
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in apiListIDs: {ex.Message}");
            return null; // Or an appropriate error response
        }
    }



    private static async Task<string> apiListIDs(ILogger log)
    {
        try
        {
            string idsFilePath = "IDs.txt";
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{idsFilePath}";

            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                var contentObject = JsonConvert.DeserializeObject<dynamic>(jsonResponse);

                if (contentObject != null && contentObject.content != null)
                {
                    byte[] data = Convert.FromBase64String(contentObject.content.ToString());
                    return Encoding.UTF8.GetString(data);
                }
                else
                {
                    log.LogInformation("IDs.txt file is empty or does not exist.");
                    return null; // Or an appropriate response
                }
            }
            else
            {
                log.LogError($"Failed to retrieve IDs.txt file. Status: {response.StatusCode}");
                return null; // Or an appropriate response
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in apiListIDs: {ex.Message}");
            return null; // Or an appropriate error response
        }
    }

    public static async Task CreateAndUploadZipFile(string id, string content, string fileName, ILogger log)
    {
        string timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
        string zipFileName = $"{id}/{timestamp}_{fileName}.zip"; // Adjusted to use fileName in zip file name
        string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{zipFileName}";

        using (var compressedFileStream = new MemoryStream())
        {
            using (var archive = new ZipArchive(compressedFileStream, ZipArchiveMode.Create, true))
            {
                // Use provided fileName for the entry inside the zip
                var zipEntry = archive.CreateEntry(fileName, CompressionLevel.Optimal);
                using (var zipEntryStream = zipEntry.Open())
                using (var streamWriter = new StreamWriter(zipEntryStream))
                {
                    await streamWriter.WriteAsync(content);
                }
            }

            compressedFileStream.Seek(0, SeekOrigin.Begin);
            byte[] zipBytes = compressedFileStream.ToArray();
            string base64ZipContent = Convert.ToBase64String(zipBytes);

            // Use the existing UpdateFileContent method without modification
            await UpdateFileContent(githubUrl, base64ZipContent);
        }
    }


    private static async Task CreateFile(string fileName, string content = "")
    {
        string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ghToken);

        var updatePayload = new
        {
            message = $"Create {fileName}",
            content = Convert.ToBase64String(Encoding.UTF8.GetBytes(content))
        };
        var updateContent = new StringContent(JsonConvert.SerializeObject(updatePayload), Encoding.UTF8, "application/json");

        await httpClient.PutAsync(githubUrl, updateContent);
    }

    private static async Task<IActionResult> ReadFromAgentFile(string id, string fileType, ILogger log)
    {
        try
        {
            string fileName = $"{id}/{fileType}.txt";
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";

            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);
            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                var responseObject = JsonConvert.DeserializeObject<dynamic>(jsonResponse);
                string contentBase64 = responseObject.content;

                if (contentBase64 != null)
                {
                    // Decode the Base64 content to get the actual file content
                    byte[] data = Convert.FromBase64String(contentBase64.ToString());
                    string fileContent = Encoding.UTF8.GetString(data);

                    return new OkObjectResult(fileContent);
                }
                else
                {
                    return new OkObjectResult(""); // No content found
                }
            }
            else
            {
                log.LogError($"GitHub API call failed: {response.StatusCode}");
                return new StatusCodeResult((int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in ReadFromAgentFile: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }

    private static async Task<IActionResult> WriteAgentResults(string id, string resultContent, ILogger log)
    {
        try
        {
            string fileName = $"{id}/results.txt";
            string fileUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";

            // Check if the file exists
            HttpResponseMessage response = await httpClient.GetAsync(fileUrl);
            bool fileExists = response.IsSuccessStatusCode;

            string sha = null;
            if (fileExists)
            {
                var fileResponseContent = await response.Content.ReadAsStringAsync();
                dynamic fileData = JsonConvert.DeserializeObject(fileResponseContent);
                sha = fileData.sha;
            }

            var updateFileContent = new
            {
                message = $"Updating result for {id}",
                content = Convert.ToBase64String(Encoding.UTF8.GetBytes(resultContent)),
                sha = fileExists ? sha : null
            };

            HttpMethod method = fileExists ? HttpMethod.Put : HttpMethod.Post;
            var requestMessage = new HttpRequestMessage(method, fileUrl)
            {
                Content = new StringContent(JsonConvert.SerializeObject(updateFileContent), Encoding.UTF8, "application/json")
            };

            HttpResponseMessage updateResponse = await httpClient.SendAsync(requestMessage);

            if (updateResponse.IsSuccessStatusCode)
            {
                return new OkObjectResult($"Result successfully written to {fileName}.");
            }
            else
            {
                log.LogError($"Failed to write result. Status: {updateResponse.StatusCode}");
                return new StatusCodeResult((int)updateResponse.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in WriteAgentResults: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }




    private static async Task<IActionResult> WriteResult(string id, string resultContent, ILogger log)
    {
        try
        {
            /*                // Create the directory with the ID if it doesn't exist
                            string directoryPath = $"{id}/";
                            await CreateFile(directoryPath);*/

            // Write result to /{id}/results.txt
            string fileName = $"{id}/results.txt";
            string fileUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";
            await CreateFile(fileUrl, resultContent);

            return new OkObjectResult($"Result written to {fileName}.");
        }
        catch (Exception ex)
        {
            log.LogError($"Error in WriteResult: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }


    // blocked by ID check
    /*        private static async Task<IActionResult> WriteResult(string id, string resultContent, ILogger log)
            {
                try
                {
                    // Check if the ID is registered in IDs.txt
                    string idsFilePath = "IDs.txt";
                    string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{idsFilePath}";
                    HttpResponseMessage idsResponse = await httpClient.GetAsync(githubUrl);

                    if (idsResponse.IsSuccessStatusCode)
                    {
                        var idsJsonResponse = await idsResponse.Content.ReadAsStringAsync();
                        var idsContentObject = JsonConvert.DeserializeObject<dynamic>(idsJsonResponse);
                        string idsBase64Content = idsContentObject.content;

                        if (idsBase64Content != null)
                        {
                            // Decode the Base64 content to get the actual IDs content
                            byte[] idsData = Convert.FromBase64String(idsBase64Content.ToString());
                            string idsFileContent = Encoding.UTF8.GetString(idsData);

                            // Check if the ID is in IDs.txt
                            if (idsFileContent.Contains(id))
                            {
                                // Create the directory with the ID if it doesn't exist
                                string directoryPath = $"{id}/";
                                await CreateFile(directoryPath);

                                // Write result to /{id}/results.txt
                                string fileName = $"{id}/results.txt";
                                string fileUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";
                                await CreateFile(fileUrl, resultContent);

                                return new OkObjectResult($"Result written to {fileName}.");
                            }
                            else
                            {
                                return new BadRequestObjectResult("ID is not registered.");
                            }
                        }
                    }

                    return new BadRequestObjectResult("ID is not registered.");
                }
                catch (Exception ex)
                {
                    log.LogError($"Error in WriteResult: {ex.Message}");
                    return new StatusCodeResult(StatusCodes.Status500InternalServerError);
                }
            }*/


    public static async Task<string[]> GetBlocklistFromGitHubAsync(ILogger log)
    {
        try
        {
            string fileName = "blocklist.txt";
            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{fileName}";
            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);

            if (response.IsSuccessStatusCode)
            {
                string blocklistContent = await response.Content.ReadAsStringAsync();
                return blocklistContent.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            }
            else
            {
                log.LogError($"GitHub API call failed: {response.StatusCode}");
                throw new Exception($"Failed to fetch blocklist from GitHub. Status code: {response.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in GetBlocklistFromGitHubAsync: {ex.Message}");
            throw new Exception("Failed to fetch blocklist from GitHub.", ex);
        }
    }


    private static async Task<IActionResult> ReadFromFile(string githubUrl, ILogger log)
    {
        try
        {
            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);
            if (response.IsSuccessStatusCode)
            {
                var jsonResponse = await response.Content.ReadAsStringAsync();
                return new OkObjectResult(jsonResponse);
            }
            else
            {
                log.LogError($"GitHub API call failed: {response.StatusCode}");
                return new StatusCodeResult((int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in ReadFromFile: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }

    private static async Task UpdateFileContent(string githubUrl, string updatedContent)
    {
        try
        {
            // Get the current SHA of the file
            HttpResponseMessage shaResponse = await httpClient.GetAsync(githubUrl);
            if (!shaResponse.IsSuccessStatusCode)
            {
                // Handle the error appropriately (e.g., log or throw an exception)
                return;
            }

            var shaContent = await shaResponse.Content.ReadAsStringAsync();
            var shaObject = JObject.Parse(shaContent);
            var sha = shaObject["sha"]?.ToString();

            // Create the update payload
            var updatePayload = new
            {
                message = $"Update file content",
                content = Convert.ToBase64String(Encoding.UTF8.GetBytes(updatedContent)),
                sha = sha
            };
            var updateContent = new StringContent(JsonConvert.SerializeObject(updatePayload), Encoding.UTF8, "application/json");

            // Construct the HTTP request for updating the file
            var requestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Put,
                RequestUri = new Uri(githubUrl),
                Content = updateContent
            };

            // Set authorization headers
            requestMessage.Headers.Add("Authorization", $"Bearer {ghToken}");
            requestMessage.Headers.Add("User-Agent", "AppName/1.0");

            // Perform the update operation
            HttpResponseMessage updateResponse = await httpClient.SendAsync(requestMessage);

            if (!updateResponse.IsSuccessStatusCode)
            {
                // Handle the update failure appropriately (e.g., log or throw an exception)
                return;
            }

            // Log that the file content was updated successfully
            Console.WriteLine("File content updated successfully.");
        }
        catch (Exception ex)
        {
            // Handle any exceptions that occur during the update (e.g., log or throw an exception)
            Console.WriteLine($"Error in UpdateFileContent: {ex.Message}");
        }
    }

    private static async Task CreateFolder(string folderPath, ILogger log)
    {
        string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{folderPath}";

        var createFolderPayload = new
        {
            message = $"Create folder {folderPath}",
            content = ""
        };

        var createFolderContent = new StringContent(JsonConvert.SerializeObject(createFolderPayload), Encoding.UTF8, "application/json");

        HttpResponseMessage createFolderResponse = await httpClient.PutAsync(githubUrl, createFolderContent);

        if (!createFolderResponse.IsSuccessStatusCode)
        {
            log.LogError($"Failed to create folder {folderPath}. Status code: {createFolderResponse.StatusCode}");
            throw new Exception($"Failed to create folder {folderPath}");
        }

        log.LogInformation($"Folder {folderPath} created successfully.");
    }

    private static async Task CreateCheckinFile(string id, ILogger log)
    {
        string checkinFilePath = $"{id}/checkin.txt";
        string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{checkinFilePath}";

        // Read the first line of script.txt
        string scriptFilePath = "script.txt";
        string scriptGithubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{scriptFilePath}";
        HttpResponseMessage scriptResponse = await httpClient.GetAsync(scriptGithubUrl);

        if (!scriptResponse.IsSuccessStatusCode)
        {
            log.LogError($"Failed to read script.txt. Status code: {scriptResponse.StatusCode}");
            throw new Exception($"Failed to read script.txt");
        }

        var scriptContent = await scriptResponse.Content.ReadAsStringAsync();
        var scriptObject = JObject.Parse(scriptContent);
        string scriptBase64Content = scriptObject["content"].ToString();
        string scriptDecodedContent = Encoding.UTF8.GetString(Convert.FromBase64String(scriptBase64Content));
        string firstLine = scriptDecodedContent.Split('\n').FirstOrDefault();

        // Write the first line of script.txt into checkin.txt
        var checkinFileContent = new
        {
            message = $"Create {checkinFilePath}",
            content = Convert.ToBase64String(Encoding.UTF8.GetBytes(firstLine))
        };

        var checkinFileContentJson = new StringContent(JsonConvert.SerializeObject(checkinFileContent), Encoding.UTF8, "application/json");

        HttpResponseMessage checkinFileResponse = await httpClient.PutAsync(githubUrl, checkinFileContentJson);

        if (!checkinFileResponse.IsSuccessStatusCode)
        {
            log.LogError($"Failed to write checkin file {checkinFilePath}. Status code: {checkinFileResponse.StatusCode}");
            throw new Exception($"Failed to write checkin file {checkinFilePath}");
        }

        log.LogInformation($"Checkin file {checkinFilePath} created and written successfully.");
    }
    private static async Task WriteAgeFile(string ageFilePath, ILogger log)
    {
        string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{ageFilePath}";

        var ageFileContent = new
        {
            message = $"Create {ageFilePath}",
            content = Convert.ToBase64String(Encoding.UTF8.GetBytes(DateTime.UtcNow.ToString()))
        };

        var ageFileContentJson = new StringContent(JsonConvert.SerializeObject(ageFileContent), Encoding.UTF8, "application/json");

        HttpResponseMessage ageFileResponse = await httpClient.PutAsync(githubUrl, ageFileContentJson);

        if (!ageFileResponse.IsSuccessStatusCode)
        {
            log.LogError($"Failed to write age file {ageFilePath}. Status code: {ageFileResponse.StatusCode}");
            throw new Exception($"Failed to write age file {ageFilePath}");
        }

        log.LogInformation($"Age file {ageFilePath} created and written successfully.");
        
    }


    private static async Task<string> ReadAndRemoveCommandFromFileV2(string id, ILogger log)
    {
        try
        {


            string githubUrl = $"https://api.github.com/repos/{ghUsername}/{repoName}/contents/{id}/checkin.txt";
            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);
            if (response.IsSuccessStatusCode)
            {
                var jsonContent = await response.Content.ReadAsStringAsync();
                var contentObject = JObject.Parse(jsonContent);

                if (contentObject["content"] != null)
                {
                    string base64Content = contentObject["content"].ToString();
                    string decodedContent = Encoding.UTF8.GetString(Convert.FromBase64String(base64Content));

                    // Split the content by commas
                    string[] commands = decodedContent.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    if (commands.Length > 0)
                    {
                        string firstCommand = commands[0];
                        string[] remainingCommands = commands.Skip(1).ToArray();

                        // Update the file on GitHub with the remaining commands
                        await UpdateFileContent(githubUrl, string.Join(",", remainingCommands));

                        return firstCommand;
                    }
                    else
                    {
                        log.LogInformation("No commands left in the file.");
                        return "No commands left.";
                    }
                }
                else
                {
                    log.LogInformation("No content found in the file.");
                    return "No content found.";
                }
            }
            else
            {
                log.LogError($"GitHub API call failed: {response.StatusCode}");
                return null;
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in ReadAndRemoveCommandFromFile: {ex.Message}");
            return null;
        }
    }




    private static async Task<string> ReadAndRemoveCommandFromFile(string githubUrl, ILogger log)
    {
        try
        {
            HttpResponseMessage response = await httpClient.GetAsync(githubUrl);
            if (response.IsSuccessStatusCode)
            {
                var jsonContent = await response.Content.ReadAsStringAsync();
                var contentObject = JObject.Parse(jsonContent);

                if (contentObject["content"] != null)
                {
                    string base64Content = contentObject["content"].ToString();
                    string decodedContent = Encoding.UTF8.GetString(Convert.FromBase64String(base64Content));

                    // Split the content by commas
                    string[] commands = decodedContent.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    if (commands.Length > 0)
                    {
                        string firstCommand = commands[0];
                        string[] remainingCommands = commands.Skip(1).ToArray();

                        // Update the file on GitHub with the remaining commands
                        await UpdateFileContent(githubUrl, string.Join(",", remainingCommands));

                        return firstCommand;
                    }
                    else
                    {
                        log.LogInformation("No commands left in the file.");
                        return "No commands left.";
                    }
                }
                else
                {
                    log.LogInformation("No content found in the file.");
                    return "No content found.";
                }
            }
            else
            {
                log.LogError($"GitHub API call failed: {response.StatusCode}");
                return null;
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in ReadAndRemoveCommandFromFile: {ex.Message}");
            return null;
        }
    }

    public static async Task AppendRequestToFile(string githubUrl, string content, HttpRequest req, ILogger log)
    {
        try
        {
            // Fetch the current file SHA
            var shaResponse = await httpClient.GetAsync(githubUrl);
            string sha = null;
            string existingContent = "";

            if (shaResponse.IsSuccessStatusCode)
            {
                var shaContent = await shaResponse.Content.ReadAsStringAsync();
                var shaObject = JsonConvert.DeserializeObject<dynamic>(shaContent);
                sha = shaObject["sha"].ToString();

                // Decode existing content if file exists
                string encodedContent = shaObject["content"].ToString();
                if (!string.IsNullOrEmpty(encodedContent))
                {
                    byte[] decodedBytes = Convert.FromBase64String(encodedContent);
                    existingContent = Encoding.UTF8.GetString(decodedBytes);
                }
            }

            // Read the new content to be written
            string newContent = content;
            string updatedContent = string.IsNullOrEmpty(existingContent) ? newContent : $"{existingContent}\n{newContent}";

            byte[] updatedBytes = Encoding.UTF8.GetBytes(updatedContent);
            string base64UpdatedContent = Convert.ToBase64String(updatedBytes);

            // Create the update payload
            var updatePayload = new
            {
                message = $"Update {githubUrl}",
                content = base64UpdatedContent,
                sha = sha // This can be null if the file doesn't exist
            };
            var updateContent = new StringContent(JsonConvert.SerializeObject(updatePayload), Encoding.UTF8, "application/json");

            // Send the update request
            HttpResponseMessage updateResponse = await httpClient.PutAsync(githubUrl, updateContent);
            if (updateResponse.IsSuccessStatusCode)
            {
                string jsonResponse = await updateResponse.Content.ReadAsStringAsync();
                log.LogInformation($"GitHub API update call succeeded: {jsonResponse}");
            }
            else
            {
                log.LogError($"GitHub API update call failed: {updateResponse.StatusCode}");
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in AppendRequestToFile: {ex.Message}");
        }
    }

    // Added for the Sadrat Console

    public static async Task<IActionResult> AppendCheckinV2(string githubUrl, string id, HttpRequest req, ILogger log)
    {
        try
        {
            string fileType = "checkin.txt";
            string completeUrl = $"{githubUrl}/{id}/{fileType}";

            // Fetch the current file SHA
            var shaResponse = await httpClient.GetAsync(completeUrl);
            string sha = null;
            string existingContent = "";

            if (shaResponse.IsSuccessStatusCode)
            {
                var shaContent = await shaResponse.Content.ReadAsStringAsync();
                dynamic shaObject = JsonConvert.DeserializeObject(shaContent);
                sha = shaObject.sha;

                // Decode existing content if the file exists
                string encodedContent = shaObject.content;
                if (!string.IsNullOrEmpty(encodedContent))
                {
                    byte[] decodedBytes = Convert.FromBase64String(encodedContent);
                    existingContent = Encoding.UTF8.GetString(decodedBytes);
                }
            }

            // Read the new content to be written
            string newContent = await new StreamReader(req.Body).ReadToEndAsync();
            string updatedContent = $"{existingContent}\n{newContent}";

            byte[] updatedBytes = Encoding.UTF8.GetBytes(updatedContent);
            string base64UpdatedContent = Convert.ToBase64String(updatedBytes);

            // Create the update payload
            var updatePayload = new
            {
                message = $"Update {fileType}",
                content = base64UpdatedContent,
                sha // This can be null if the file doesn't exist
            };
            var updateContent = new StringContent(JsonConvert.SerializeObject(updatePayload), Encoding.UTF8, "application/json");

            // Send the update request
            HttpResponseMessage updateResponse = await httpClient.PutAsync(completeUrl, updateContent);
            if (updateResponse.IsSuccessStatusCode)
            {
                return new JsonResult(new { Message = "Operation successful." });
            }
            else
            {
                log.LogError($"GitHub API update call failed: {updateResponse.StatusCode}");
                return new StatusCodeResult((int)updateResponse.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in AppendCheckinV2: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }




    public static async Task<IActionResult> AppendResultsV2(string githubUrl, string id, HttpRequest req, ILogger log)
    {
        try
        {
            // Construct the file URL based on the provided ID and fileType
            string fileType = "results.txt";
            githubUrl = $"{githubUrl}/{id}/{fileType}";

            // Fetch the current file SHA
            var shaResponse = await httpClient.GetAsync(githubUrl);
            string sha = null;
            string existingContent = "";

            if (shaResponse.IsSuccessStatusCode)
            {
                var shaContent = await shaResponse.Content.ReadAsStringAsync();
                var shaObject = JsonConvert.DeserializeObject<dynamic>(shaContent);
                sha = shaObject["sha"].ToString();

                // Decode existing content if the file exists
                string encodedContent = shaObject["content"].ToString();
                if (!string.IsNullOrEmpty(encodedContent))
                {
                    byte[] decodedBytes = Convert.FromBase64String(encodedContent);
                    existingContent = Encoding.UTF8.GetString(decodedBytes);
                }
            }

            // Read the new content to be written
            string newContent = await new StreamReader(req.Body).ReadToEndAsync();
            string updatedContent = string.IsNullOrEmpty(existingContent) ? newContent : $"{existingContent}\n{newContent}";

            // Check if the filename is "results.txt" and it already exists
            if (fileType == "results.txt" && !string.IsNullOrEmpty(existingContent))
            {
                // Append to the existing content if the file already exists
                updatedContent = $"{existingContent}\n{newContent}";
            }

            byte[] updatedBytes = Encoding.UTF8.GetBytes(updatedContent);
            string base64UpdatedContent = Convert.ToBase64String(updatedBytes);

            // Create the update payload
            var updatePayload = new
            {
                message = $"Update {fileType}",
                content = base64UpdatedContent,
                sha = sha // This can be null if the file doesn't exist
            };
            var updateContent = new StringContent(JsonConvert.SerializeObject(updatePayload), Encoding.UTF8, "application/json");

            // Send the update request
            HttpResponseMessage updateResponse = await httpClient.PutAsync(githubUrl, updateContent);
            if (updateResponse.IsSuccessStatusCode)
            {
                string jsonResponse = await updateResponse.Content.ReadAsStringAsync();
                /*return new OkObjectResult(jsonResponse);*/
                return new JsonResult(new { Message = "Operation successful." });
            }
            else
            {
                log.LogError($"GitHub API update call failed: {updateResponse.StatusCode}");
                return new StatusCodeResult((int)updateResponse.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in AppendResultsV2: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }






    public static async Task<IActionResult> AppendToFile(string githubUrl, string fileName, HttpRequest req, ILogger log)
    {
        try
        {
            // Fetch the current file SHA
            var shaResponse = await httpClient.GetAsync(githubUrl);
            string sha = null;
            string existingContent = "";

            if (shaResponse.IsSuccessStatusCode)
            {
                var shaContent = await shaResponse.Content.ReadAsStringAsync();
                var shaObject = JsonConvert.DeserializeObject<dynamic>(shaContent);
                sha = shaObject["sha"].ToString();

                // Decode existing content if file exists
                string encodedContent = shaObject["content"].ToString();
                if (!string.IsNullOrEmpty(encodedContent))
                {
                    byte[] decodedBytes = Convert.FromBase64String(encodedContent);
                    existingContent = Encoding.UTF8.GetString(decodedBytes);
                }
            }

            // Read the new content to be written
            string newContent = await new StreamReader(req.Body).ReadToEndAsync();
            string updatedContent = string.IsNullOrEmpty(existingContent) ? newContent : $"{existingContent}\n{newContent}";

            // Check if the filename is "_results.txt" and it already exists
            if (fileName.EndsWith("_results.txt") && !string.IsNullOrEmpty(existingContent))
            {
                // Append to the existing content if the file already exists
                updatedContent = $"{existingContent}\n{newContent}";
            }

            byte[] updatedBytes = Encoding.UTF8.GetBytes(updatedContent);
            string base64UpdatedContent = Convert.ToBase64String(updatedBytes);

            // Create the update payload
            var updatePayload = new
            {
                message = $"Update {fileName}",
                content = base64UpdatedContent,
                sha = sha // This can be null if the file doesn't exist
            };
            var updateContent = new StringContent(JsonConvert.SerializeObject(updatePayload), Encoding.UTF8, "application/json");

            // Send the update request
            HttpResponseMessage updateResponse = await httpClient.PutAsync(githubUrl, updateContent);
            if (updateResponse.IsSuccessStatusCode)
            {
                string jsonResponse = await updateResponse.Content.ReadAsStringAsync();
                /*return new OkObjectResult(jsonResponse);*/
                return new JsonResult(new { Message = "Operation succesful." });

            }
            else
            {
                log.LogError($"GitHub API update call failed: {updateResponse.StatusCode}");
                return new StatusCodeResult((int)updateResponse.StatusCode);
            }
        }
        catch (Exception ex)
        {
            log.LogError($"Error in AppendToFile: {ex.Message}");
            return new StatusCodeResult(StatusCodes.Status500InternalServerError);
        }
    }
}
