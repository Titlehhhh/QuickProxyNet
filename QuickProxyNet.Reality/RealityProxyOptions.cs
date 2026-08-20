namespace QuickProxyNet.Reality;

/// <summary>
/// Knobs for how <see cref="RealityProxy"/> locates and runs Xray-core.
/// </summary>
public sealed class RealityProxyOptions
{
    /// <summary>
    /// Environment variable consulted when <see cref="ExecutablePath"/> is null.
    /// </summary>
    public const string ExecutablePathVariable = "QPN_XRAY_PATH";

    /// <summary>
    /// Full path to the Xray-core executable. When null the resolver falls back to
    /// <see cref="ExecutablePathVariable"/> and then to <c>PATH</c>.
    /// </summary>
    /// <remarks>
    /// This package does <b>not</b> ship a binary. Xray-core is MPL-2.0 and platform-specific;
    /// bundling it would make a NuGet package a redistributor of a censorship-circumvention
    /// binary, with the download size and antivirus consequences that implies. Pointing at a
    /// binary the caller already trusts keeps that decision with the caller.
    /// </remarks>
    public string? ExecutablePath { get; init; }

    /// <summary>Loopback address for the local SOCKS5 inbound. Defaults to <c>127.0.0.1</c>.</summary>
    /// <remarks>
    /// Loopback is not a default to override casually: the inbound has no authentication, so
    /// binding it to a routable address exposes an open proxy to the network.
    /// </remarks>
    public string ListenAddress { get; init; } = "127.0.0.1";

    /// <summary>
    /// Fixed port for the local inbound. When null (the default) a free ephemeral port is taken.
    /// </summary>
    public int? ListenPort { get; init; }

    /// <summary>How long to wait for Xray to start accepting on the inbound.</summary>
    public TimeSpan StartupTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>Xray <c>loglevel</c>. Defaults to <c>warning</c>.</summary>
    /// <remarks>
    /// <c>info</c> and below log the destination of every connection made through the tunnel.
    /// That is exactly the record the tunnel exists to avoid producing, so verbose logging is
    /// opt-in and never the default.
    /// </remarks>
    public string LogLevel { get; init; } = "warning";

    /// <summary>
    /// Receives Xray's stdout/stderr lines when set. Null discards them.
    /// </summary>
    public Action<string>? LogSink { get; init; }
}
