using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;


public class BlocklistMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string[] _blocklist;
    private readonly ILogger _log;
    /* private string[] _blocklist;*/

    public BlocklistMiddleware(ILogger log)
    {

        _log = log;

        try
        {

            _blocklist = FileOperationFunctionV2.GetBlocklistFromGitHubAsync(log).Result;
        }
        catch (Exception ex)
        {
            _log.LogError($"Error initializing blocklist: {ex.Message}");
            _blocklist = new string[0]; // Set an empty blocklist in case of an error
        }
    }

    public bool IsBlocked(string idToCheck)
    {
        if (_blocklist.Contains(idToCheck))
        {
            return true; // ID is in the blocklist
        }
        return false;
    }

    public async Task InvokeAsyncLast(HttpContext context)
    {
        string id = GetIdFromLastSegment(context.Request.Path.Value);

        if (!string.IsNullOrEmpty(id))
        {
            if (IsBlocked(id))
            {
                context.Response.StatusCode = 403; // Forbidden
                await context.Response.WriteAsync("Access denied: Agent is blocked.");
            }
            else
            {
                await _next(context); // Continue with the next middleware
            }
        }
        else
        {
            // Handle the case where no valid ID is found in the route
            context.Response.StatusCode = 400; // Bad Request
            await context.Response.WriteAsync("No valid 'ID' parameter found in the route.");
        }
    }

    public async Task InvokeAsyncMiddle(HttpContext context)
    {
        string id = GetIdFromSecondToLastSegment(context.Request.Path.Value);

        if (!string.IsNullOrEmpty(id))
        {
            if (IsBlocked(id))
            {
                context.Response.StatusCode = 403; // Forbidden
                await context.Response.WriteAsync("Access denied: Agent is blocked.");
            }
            else
            {
                await _next(context); // Continue with the next middleware
            }
        }
        else
        {
            // Handle the case where no valid ID is found in the route
            context.Response.StatusCode = 400; // Bad Request
            await context.Response.WriteAsync("No valid 'ID' parameter found in the route.");
        }
    }



    private string GetIdFromLastSegment(string url)
    {
        string[] segments = url?.Split('/');
        if (segments != null && segments.Length > 0)
        {
            return segments.Last();
        }
        return null;
    }

    private string GetIdFromSecondToLastSegment(string url)
    {
        string[] segments = url?.Split('/');
        if (segments != null && segments.Length > 1)
        {
            return segments[segments.Length - 2];
        }
        return null;
    }

}
