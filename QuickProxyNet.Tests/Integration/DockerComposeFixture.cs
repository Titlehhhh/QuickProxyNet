using System.Diagnostics;
using System.Net.Sockets;
using System.Text;

namespace QuickProxyNet.Tests.Integration;

/// <summary>
/// Owns the lifetime of <c>tests/docker/docker-compose.yml</c> for the docker integration tests.
/// </summary>
/// <remarks>
/// <para>
/// The compose project name is pinned to <see cref="ProjectName"/> so an interrupted run can
/// always be cleaned up by hand with the exact same command
/// (<c>docker compose -p quickproxynet-test -f tests/docker/docker-compose.yml down -v</c>),
/// and so two runs never collide with generated names.
/// </para>
/// <para>
/// <see cref="DisposeAsync"/> runs <c>down -v</c> unconditionally in a <c>finally</c>: if
/// <c>up</c> got far enough to create anything at all, teardown happens even when startup
/// failed halfway. After a run <c>docker ps</c> must be empty.
/// </para>
/// <para>
/// Startup failures are captured rather than thrown. A throwing <c>InitializeAsync</c> surfaces
/// in xUnit as an opaque collection-level error; storing the reason lets every test fail with
/// the actual docker output.
/// </para>
/// <para>
/// The stack is a <b>machine-global singleton</b>: one fixed project name, one fixed set of host
/// ports. Two test processes therefore cannot own it at once — and <c>dotnet test</c> on a
/// multi-targeted project runs the TFMs concurrently, so that is the normal case, not an exotic
/// one. <see cref="AcquireGlobalLockAsync"/> serializes them; each run brings the stack up, uses
/// it, and tears it down before the next acquires the lock.
/// </para>
/// </remarks>
public sealed class DockerComposeFixture : IAsyncLifetime
{
    /// <summary>The fixed compose project name. Never generate this.</summary>
    public const string ProjectName = "quickproxynet-test";

    /// <summary>
    /// How long to wait for another test process to finish with the stack. Generous on purpose:
    /// the holder keeps the lock for its whole docker run, not just for startup.
    /// </summary>
    private static readonly TimeSpan LockTimeout = TimeSpan.FromMinutes(10);

    private bool _composeTouched;
    private FileStream? _globalLock;

    /// <summary>Absolute path of <c>tests/docker/docker-compose.yml</c>.</summary>
    public string ComposeFile { get; private set; } = "";

    /// <summary>Non-null when the stack failed to come up; the reason to fail tests with.</summary>
    public string? StartupError { get; private set; }

    /// <summary>Throws with the captured docker output when the stack is not usable.</summary>
    public void EnsureUp()
    {
        if (StartupError is not null)
            throw new InvalidOperationException(StartupError);
    }

    public async Task InitializeAsync()
    {
        // The fixture is constructed even when every test in the class is skipped at
        // discovery time, so the gate has to be re-checked here or an unconfigured run
        // would still start containers.
        if (!SkipGates.DockerEnabled)
            return;

        try
        {
            ComposeFile = LocateComposeFile();

            // Must be held before touching compose: the 'down -v' below would otherwise rip the
            // stack out from under a concurrently running test process.
            _globalLock = await AcquireGlobalLockAsync(LockTimeout);

            // Clear anything a previously interrupted run left behind before starting.
            _composeTouched = true;
            await ComposeAsync("down -v --remove-orphans", TimeSpan.FromMinutes(2));

            var up = await ComposeAsync("up -d --wait", TimeSpan.FromMinutes(5));
            if (up.ExitCode != 0)
            {
                StartupError = $"'docker compose up -d --wait' failed with exit code {up.ExitCode}.\n{up.Output}";
                return;
            }

            await WaitForListenersAsync(TimeSpan.FromSeconds(90));
        }
        catch (Exception ex)
        {
            StartupError = $"Docker compose stack failed to start: {ex}";
        }
    }

    public async Task DisposeAsync()
    {
        try
        {
            if (_composeTouched)
                await ComposeAsync("down -v --remove-orphans", TimeSpan.FromMinutes(2));
        }
        finally
        {
            _composeTouched = false;

            // Released last, so the next test process only sees a torn-down stack.
            _globalLock?.Dispose();
            _globalLock = null;
        }
    }

    /// <summary>
    /// Takes an exclusive cross-process lock on the compose stack, waiting for whoever holds it.
    /// </summary>
    /// <remarks>
    /// A lock <i>file</i> rather than a named <see cref="Mutex"/> on purpose: a mutex has thread
    /// affinity and must be released by the thread that took it, which async test lifecycle
    /// methods do not guarantee — the release would throw. A <see cref="FileStream"/> opened with
    /// <see cref="FileShare.None"/> has no such affinity and is released by disposal.
    /// </remarks>
    private static async Task<FileStream> AcquireGlobalLockAsync(TimeSpan timeout)
    {
        string path = Path.Combine(Path.GetTempPath(), "quickproxynet-docker-compose.lock");
        long deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;

        while (true)
        {
            try
            {
                return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException)
            {
                if (Environment.TickCount64 > deadline)
                    throw new TimeoutException(
                        $"Another test process has held the docker compose stack for over {timeout}. " +
                        $"If none is running, delete '{path}'.");

                await Task.Delay(250);
            }
        }
    }

    /// <summary>
    /// Polls every mapped host port until it accepts a TCP connection. This is a real
    /// readiness probe: xray and sing-box bind their listeners only once the whole config
    /// has been accepted, so an accepted connection means the inbound exists. A fixed sleep
    /// would be both slower and a lie.
    /// </summary>
    private static async Task WaitForListenersAsync(TimeSpan timeout)
    {
        long deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;

        foreach (var endpoint in DockerEndpoints.All)
        {
            while (true)
            {
                if (await TryConnectAsync(endpoint.Port))
                    break;

                if (Environment.TickCount64 > deadline)
                    throw new TimeoutException(
                        $"Port {endpoint.Port} ({endpoint.Description}) never started accepting connections.");

                await Task.Delay(200);
            }
        }
    }

    private static async Task<bool> TryConnectAsync(int port)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try
        {
            await socket.ConnectAsync("127.0.0.1", port, cts.Token);
            return true;
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            return false;
        }
    }

    private Task<(int ExitCode, string Output)> ComposeAsync(string arguments, TimeSpan timeout) =>
        RunAsync("docker", $"compose -p {ProjectName} -f \"{ComposeFile}\" {arguments}", timeout);

    private static async Task<(int ExitCode, string Output)> RunAsync(
        string fileName, string arguments, TimeSpan timeout)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException($"Could not start '{fileName} {arguments}'.");

        var output = new StringBuilder();
        var stdout = ReadAllAsync(process.StandardOutput, output);
        var stderr = ReadAllAsync(process.StandardError, output);

        using var cts = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* already gone */ }
            throw new TimeoutException($"'{fileName} {arguments}' did not finish within {timeout}.");
        }

        await Task.WhenAll(stdout, stderr);
        return (process.ExitCode, output.ToString());

        static async Task ReadAllAsync(StreamReader reader, StringBuilder sink)
        {
            string text = await reader.ReadToEndAsync();
            lock (sink)
                sink.Append(text);
        }
    }

    /// <summary>
    /// Walks up from the test binary to the repository root (identified by
    /// <c>QuickProxyNet.slnx</c>) and returns the compose file beneath it.
    /// </summary>
    private static string LocateComposeFile()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, "tests", "docker", "docker-compose.yml");
            if (File.Exists(Path.Combine(dir.FullName, "QuickProxyNet.slnx")) && File.Exists(candidate))
                return candidate;

            dir = dir.Parent;
        }

        throw new FileNotFoundException(
            $"Could not find tests/docker/docker-compose.yml above '{AppContext.BaseDirectory}'.");
    }
}
