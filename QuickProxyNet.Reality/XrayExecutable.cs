using System.Runtime.InteropServices;

namespace QuickProxyNet.Reality;

/// <summary>
/// Finds the Xray-core executable to run.
/// </summary>
internal static class XrayExecutable
{
    /// <summary>
    /// Resolves the binary from the explicit path, then <c>QPN_XRAY_PATH</c>, then <c>PATH</c>.
    /// </summary>
    /// <exception cref="FileNotFoundException">
    /// Nothing was found. The message lists every place that was searched — a caller who has to
    /// guess where the library looked cannot fix the problem.
    /// </exception>
    public static string Resolve(string? explicitPath)
    {
        if (!string.IsNullOrEmpty(explicitPath))
        {
            if (!File.Exists(explicitPath))
                throw new FileNotFoundException(
                    $"Xray-core was not found at the configured path '{explicitPath}'.", explicitPath);

            return Path.GetFullPath(explicitPath);
        }

        string? fromEnvironment = Environment.GetEnvironmentVariable(RealityProxyOptions.ExecutablePathVariable);
        if (!string.IsNullOrEmpty(fromEnvironment))
        {
            if (!File.Exists(fromEnvironment))
                throw new FileNotFoundException(
                    $"{RealityProxyOptions.ExecutablePathVariable} points at '{fromEnvironment}', " +
                    "which does not exist.", fromEnvironment);

            return Path.GetFullPath(fromEnvironment);
        }

        string fileName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "xray.exe" : "xray";
        string? onPath = SearchPath(fileName);
        if (onPath is not null)
            return onPath;

        throw new FileNotFoundException(
            $"Xray-core was not found. QuickProxyNet.Reality does not ship a binary; supply one via " +
            $"{nameof(RealityProxyOptions)}.{nameof(RealityProxyOptions.ExecutablePath)}, the " +
            $"{RealityProxyOptions.ExecutablePathVariable} environment variable, or by putting " +
            $"'{fileName}' on PATH.");
    }

    private static string? SearchPath(string fileName)
    {
        string? path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrEmpty(path))
            return null;

        foreach (string directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string candidate;
            try
            {
                candidate = Path.Combine(directory.Trim('"'), fileName);
            }
            catch (ArgumentException)
            {
                // A malformed PATH entry is not a reason to fail the whole search.
                continue;
            }

            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }
}
