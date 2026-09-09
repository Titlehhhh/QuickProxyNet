// CorpusCheck --live — MANUAL diagnostic only.
//
// This mode opens real connections to a small SAMPLE of third-party nodes taken from the
// "Checked" corpus (nodes the upstream list has already probed for reachability), tunnels
// one HTTP request to a neutral connectivity endpoint through each of them, and reports
// whether OUR client could complete the exchange.
//
// Deliberate limits, because this touches other people's infrastructure:
//
//   * It is NEVER run by CI or by the test suite. tools/CorpusCheck is not in
//     QuickProxyNet.slnx, and Main refuses to run --live when a CI environment variable is
//     present.
//   * It is a SAMPLE (default 30, hard-capped at MaxSampleSize), never a sweep of the whole
//     ~11k-line list. Nodes are de-duplicated by endpoint, so one server is touched once.
//   * Connections are SEQUENTIAL with a short per-node timeout (default 5s). One request,
//     one response, then the tunnel is closed. This is a client-correctness check, not a
//     scan and not a throughput test.
//   * Only configurations this library can actually speak are sampled (raw tcp transport,
//     security none/tls, no REALITY, no XTLS flow, no ws/grpc/xhttp). Dialling a node we
//     are guaranteed to reject teaches nothing about the client.
//
// Redaction rules are the same as the parse report and are non-negotiable: these are real
// servers with real credentials belonging to other people. Group keys come from a fixed
// taxonomy (never a raw exception message, which would embed host:port), and every example
// is a REDACTED SHAPE produced by Redactor. No response byte is ever printed.

using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using QuickProxyNet;

namespace CorpusCheck;

/// <summary>One sampled node: everything the probe needs, plus the values it must scrub.</summary>
internal sealed record LiveNode(
    string Protocol,
    string Mode,
    string Shape,
    string Host,
    int Port,
    IReadOnlyList<string?> Secrets,
    Func<ProxyClient> CreateClient);

/// <summary>Outcome of one probe: either a success mode or a taxonomy failure reason.</summary>
internal readonly record struct LiveResult(bool Ok, string Detail, TimeSpan Elapsed);

/// <summary>
/// Picks a small, protocol-balanced sample of nodes this library can actually dial.
/// </summary>
internal static class LiveSampler
{
    /// <summary>Protocols sampled, in round-robin order.</summary>
    private static readonly string[] Order = ["vless", "trojan", "vmess", "ss"];

    public static LiveSample Build(string corpusPath, int count, int seed)
    {
        var pools = new Dictionary<string, Pool>(StringComparer.Ordinal)
        {
            ["vless"] = new(),
            ["trojan"] = new(),
            ["vmess"] = new(),
            ["ss"] = new()
        };

        // One server, one probe: several share links often point at the same endpoint.
        var seenEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string rawLine in File.ReadLines(corpusPath))
        {
            string line = rawLine.Trim();
            if (line.Length == 0)
                continue;

            if (line.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
                ConsiderVless(pools["vless"], line, seenEndpoints);
            else if (line.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
                ConsiderTrojan(pools["trojan"], line, seenEndpoints);
            else if (line.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
                ConsiderVmess(pools["vmess"], line, seenEndpoints);
            else if (line.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
                ConsiderShadowsocks(pools["ss"], line, seenEndpoints);
        }

        var rng = new Random(seed);
        foreach (var pool in pools.Values)
            Shuffle(pool.Eligible, rng);

        // Round-robin across protocols so the report says something about each, spilling
        // over to whichever pools still have nodes when one runs dry.
        var sample = new List<LiveNode>(count);
        var cursors = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (string protocol in Order)
            cursors[protocol] = 0;

        bool progressed = true;
        while (sample.Count < count && progressed)
        {
            progressed = false;
            foreach (string protocol in Order)
            {
                if (sample.Count >= count)
                    break;
                var pool = pools[protocol];
                int cursor = cursors[protocol];
                if (cursor >= pool.Eligible.Count)
                    continue;
                sample.Add(pool.Eligible[cursor]);
                cursors[protocol] = cursor + 1;
                progressed = true;
            }
        }

        return new LiveSample(sample, pools);
    }

    private static void ConsiderVless(Pool pool, string line, HashSet<string> seen)
    {
        pool.Seen++;

        if (IsHtmlEscaped(pool, line))
            return;

        if (!VlessShareLink.TryParse(line, out var options))
        {
            pool.Exclude("does not parse");
            return;
        }

        string transport = options.Transport.ToLowerInvariant();
        if (!IsRawTcp(transport))
        {
            pool.Exclude($"transport={transport} (not implemented)");
            return;
        }
        if (options.Security == VlessSecurity.Reality)
        {
            pool.Exclude("security=reality (not implemented)");
            return;
        }
        if (!string.IsNullOrEmpty(options.Flow))
        {
            // A flow value is an XTLS mode name ("xtls-rprx-vision"), not a credential.
            pool.Exclude($"flow={options.Flow.ToLowerInvariant()} (XTLS not implemented)");
            return;
        }
        if (!IsDialable(pool, options.Host, options.Port, seen))
            return;

        string security = options.Security == VlessSecurity.Tls ? "tls" : "none";
        pool.Eligible.Add(new LiveNode(
            "vless",
            $"security={security}",
            Redactor.RedactUriLink(line),
            options.Host,
            options.Port,
            [options.Host, options.Sni, options.Id, options.Remark],
            () => new VlessClient(options)));
    }

    private static void ConsiderShadowsocks(Pool pool, string line, HashSet<string> seen)
    {
        pool.Seen++;

        if (IsHtmlEscaped(pool, line))
            return;

        if (!ShadowsocksShareLink.TryParse(line, out var options))
        {
            pool.Exclude("does not parse");
            return;
        }

        if (options.Plugin is { Length: > 0 } plugin)
        {
            pool.Exclude($"plugin={plugin.Split(';', 2)[0].ToLowerInvariant()} (not implemented)");
            return;
        }

        ShadowsocksClient client;
        try
        {
            client = new ShadowsocksClient(options);
        }
        catch (NotSupportedException ex)
        {
            pool.Exclude(Redactor.NormalizeReason(ex.Message));
            return;
        }
        catch (ArgumentException)
        {
            pool.Exclude("unusable method/password");
            return;
        }

        if (!IsDialable(pool, options.Host, options.Port, seen))
            return;

        pool.Eligible.Add(new LiveNode(
            "ss",
            $"method={options.Method.ToLowerInvariant()}",
            Redactor.RedactSsLink(line),
            options.Host,
            options.Port,
            [options.Host, options.Password, options.Remark],
            () => client));
    }

    private static void ConsiderTrojan(Pool pool, string line, HashSet<string> seen)
    {
        pool.Seen++;

        if (IsHtmlEscaped(pool, line))
            return;

        if (!TrojanShareLink.TryParse(line, out var options))
        {
            pool.Exclude("does not parse");
            return;
        }

        string transport = options.Transport.ToLowerInvariant();
        if (!IsRawTcp(transport))
        {
            pool.Exclude($"transport={transport} (not implemented)");
            return;
        }
        if (!IsDialable(pool, options.Host, options.Port, seen))
            return;

        pool.Eligible.Add(new LiveNode(
            "trojan",
            "security=tls",
            Redactor.RedactUriLink(line),
            options.Host,
            options.Port,
            [options.Host, options.Sni, options.Password, options.Remark],
            () => new TrojanClient(options)));
    }

    private static void ConsiderVmess(Pool pool, string line, HashSet<string> seen)
    {
        pool.Seen++;

        if (IsHtmlEscaped(pool, line))
            return;

        // A non-zero alterId is rejected by the parser (legacy MD5 header), so anything that
        // parses is already AEAD/alterId=0.
        if (!VmessShareLink.TryParse(line, out var options))
        {
            pool.Exclude("does not parse");
            return;
        }

        string transport = options.Transport.ToLowerInvariant();
        if (!IsRawTcp(transport))
        {
            pool.Exclude($"net={transport} (not implemented)");
            return;
        }
        if (!IsDialable(pool, options.Host, options.Port, seen))
            return;

        pool.Eligible.Add(new LiveNode(
            "vmess",
            $"tls={(options.UseTls ? "on" : "off")}",
            Redactor.RedactVmessLink(line),
            options.Host,
            options.Port,
            [options.Host, options.Sni, options.Id, options.Remark],
            () => new VmessClient(options)));
    }

    /// <summary>
    /// Rejects share links whose query separators arrived HTML-escaped as <c>&amp;amp;</c>.
    /// </summary>
    /// <remarks>
    /// The parser splits the query on <c>'&amp;'</c>, so such a link yields keys named
    /// <c>amp;security</c>, <c>amp;flow</c>, <c>amp;pbk</c> … — the real mode is invisible
    /// and a REALITY/XTLS node parses as <c>security=none</c>. The first live run sampled
    /// three of these and they failed exactly as an un-speakable config would. They are
    /// excluded (not silently dropped) so the sample measures the client while the count
    /// keeps the parser behaviour visible in the report.
    /// </remarks>
    private static bool IsHtmlEscaped(Pool pool, string line)
    {
        if (!line.Contains("&amp;", StringComparison.OrdinalIgnoreCase))
            return false;

        pool.Exclude("HTML-escaped '&amp;' query — real mode is unreadable, so connectability is unknown");
        return true;
    }

    /// <summary>
    /// Endpoint-level filters shared by all three protocols: a usable port, an IPv4-capable
    /// host, and no endpoint we have already queued.
    /// </summary>
    private static bool IsDialable(Pool pool, string host, int port, HashSet<string> seen)
    {
        if (string.IsNullOrEmpty(host) || port is <= 0 or > 65535)
        {
            pool.Exclude("unusable host/port");
            return false;
        }

        // ProxyClient creates an AddressFamily.InterNetwork socket, so an IPv6 literal can
        // never be dialled. Excluded rather than counted as a node failure.
        if (host.Contains(':'))
        {
            pool.Exclude("IPv6 literal host (client socket is IPv4-only)");
            return false;
        }

        if (!seen.Add($"{host}:{port}"))
        {
            pool.Exclude("duplicate endpoint");
            return false;
        }

        return true;
    }

    private static bool IsRawTcp(string transport) =>
        transport is "tcp" or "raw";

    private static void Shuffle(List<LiveNode> nodes, Random rng)
    {
        for (int i = nodes.Count - 1; i > 0; i--)
        {
            int j = rng.Next(i + 1);
            (nodes[i], nodes[j]) = (nodes[j], nodes[i]);
        }
    }

    internal sealed class Pool
    {
        public int Seen;
        public readonly List<LiveNode> Eligible = [];
        public readonly Dictionary<string, int> Exclusions = new(StringComparer.Ordinal);

        public void Exclude(string reason) =>
            Exclusions[reason] = Exclusions.GetValueOrDefault(reason) + 1;
    }
}

/// <summary>The chosen sample plus the eligibility bookkeeping behind it.</summary>
internal sealed record LiveSample(List<LiveNode> Nodes, Dictionary<string, LiveSampler.Pool> Pools);

/// <summary>
/// Dials one node and tunnels a single HTTP request to a neutral connectivity endpoint.
/// </summary>
/// <remarks>
/// The request/response round trip is the whole point: VLESS and VMess both validate their
/// response header LAZILY on the first read, so <c>ConnectAsync</c> returning a stream
/// proves nothing at all. A rejected handshake only surfaces once we have written a request
/// and tried to read the answer.
/// </remarks>
internal sealed class LiveProber(TimeSpan timeout)
{
    // Neutral, purpose-built connectivity endpoint: answers "204 No Content" with no body.
    // Plain HTTP on purpose — a second TLS layer inside the tunnel would only add a failure
    // mode that says nothing about our proxy client.
    public const string TargetHost = "cp.cloudflare.com";
    public const int TargetPort = 80;
    public const string TargetPath = "/generate_204";

    private static readonly byte[] Request = Encoding.ASCII.GetBytes(
        $"GET {TargetPath} HTTP/1.1\r\n" +
        $"Host: {TargetHost}\r\n" +
        "User-Agent: QuickProxyNet-CorpusCheck/1.0\r\n" +
        "Accept: */*\r\n" +
        "Connection: close\r\n\r\n");

    public async Task<LiveResult> ProbeAsync(LiveNode node, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        string phase = "connect";
        Stream? stream = null;

        try
        {
            var client = node.CreateClient();
            client.ReadTimeout = (int)timeout.TotalMilliseconds;
            client.WriteTimeout = (int)timeout.TotalMilliseconds;

            // ConnectAsync's own timer aborts the socket, but DNS resolution happens before
            // the socket exists, so keep an outer hard bound as well.
            stream = await client.ConnectAsync(TargetHost, TargetPort, timeout, cancellationToken)
                .AsTask()
                .WaitAsync(timeout + TimeSpan.FromSeconds(3), cancellationToken)
                .ConfigureAwait(false);

            phase = "request";
            await stream.WriteAsync(Request, cancellationToken)
                .AsTask().WaitAsync(Remaining(sw), cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken)
                .WaitAsync(Remaining(sw), cancellationToken).ConfigureAwait(false);

            phase = "response";
            var buffer = new byte[256];
            int total = 0;
            while (total < 16)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(total), cancellationToken)
                    .AsTask().WaitAsync(Remaining(sw), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    break;
                total += read;
            }

            return Evaluate(buffer, total, sw.Elapsed);
        }
        catch (Exception ex)
        {
            return new LiveResult(false, Classify(ex, phase, node), sw.Elapsed);
        }
        finally
        {
            if (stream is not null)
                await stream.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Time left in this node's budget, floored so WaitAsync never gets a negative.</summary>
    private TimeSpan Remaining(Stopwatch sw)
    {
        var left = timeout - sw.Elapsed;
        return left < TimeSpan.FromMilliseconds(250) ? TimeSpan.FromMilliseconds(250) : left;
    }

    /// <summary>
    /// Decides whether a plausible HTTP response came back. Only the status code and the
    /// byte count ever reach the report — never the bytes themselves.
    /// </summary>
    private static LiveResult Evaluate(byte[] buffer, int total, TimeSpan elapsed)
    {
        if (total == 0)
            return new LiveResult(false, "response: tunnel opened but server closed without sending a byte", elapsed);

        string head = Encoding.ASCII.GetString(buffer, 0, Math.Min(total, 32));
        if (!head.StartsWith("HTTP/1.", StringComparison.Ordinal))
            return new LiveResult(false, $"response: not HTTP ({total} bytes returned)", elapsed);

        string[] parts = head.Split(' ');
        string status = parts.Length > 1 && parts[1].Length == 3 && parts[1].All(char.IsAsciiDigit)
            ? parts[1]
            : "unparseable status";
        return new LiveResult(true, $"HTTP {status}", elapsed);
    }

    /// <summary>
    /// Maps an exception onto a stable, non-identifying group key. Exception messages from
    /// this library embed <c>host:port</c>, so they are never used verbatim: the key is built
    /// from types, <see cref="ProxyErrorCode"/> and <see cref="SocketError"/>, and any BCL
    /// message that does get quoted is scrubbed of this node's own secrets first.
    /// </summary>
    private static string Classify(Exception ex, string phase, LiveNode node)
    {
        switch (ex)
        {
            case TimeoutException:
                return $"{phase}: timed out";

            case OperationCanceledException:
                return $"{phase}: cancelled";

            // The library's own timer aborts the socket, so a timeout arrives as
            // SocketError.OperationAborted wrapped in ProxyErrorCode.Timeout. Report what it
            // means, not the mechanism, and keep it in the same group as other timeouts.
            case ProxyProtocolException { ErrorCode: ProxyErrorCode.Timeout }:
                return $"{phase}: timed out";

            case ProxyProtocolException pex when Inner<SocketException>(pex) is { } socket:
                return $"{phase}: SocketError.{socket.SocketErrorCode} (ProxyErrorCode.{pex.ErrorCode})";

            case ProxyProtocolException pex when Inner<AuthenticationException>(pex) is { } auth:
                return $"{phase}: TLS handshake failed (ProxyErrorCode.{pex.ErrorCode}): {Detail(auth, node)}";

            case ProxyProtocolException pex:
                return $"{phase}: ProxyErrorCode.{pex.ErrorCode}{Hint(pex.ErrorCode, phase)}";

            case AuthenticationException auth:
                return $"{phase}: TLS handshake failed: {Detail(auth, node)}";

            case SocketException socket:
                return $"{phase}: SocketError.{socket.SocketErrorCode}";

            case IOException io when Inner<SocketException>(io) is { } socket:
                return $"{phase}: I/O SocketError.{socket.SocketErrorCode}";

            case IOException io:
                return $"{phase}: IOException: {Detail(io, node)}";

            // The sampler is supposed to exclude everything the clients reject; if one slips
            // through, that mismatch is itself the finding.
            case NotSupportedException:
                return $"{phase}: NotSupportedException — sampling filter let an unsupported config through: {Detail(ex, node)}";

            default:
                return $"{phase}: unexpected {ex.GetType().Name}: {Detail(ex, node)}";
        }
    }

    /// <summary>
    /// Fixed explanatory suffix for the codes whose meaning depends on the phase. During
    /// the response phase a <see cref="ProxyErrorCode.ConnectionFailed"/> is not a TCP
    /// failure at all: it is the lazy response-header read finding the connection dropped,
    /// which is how VLESS and VMess servers reject a handshake.
    /// </summary>
    private static string Hint(ProxyErrorCode code, string phase) => (code, phase) switch
    {
        (ProxyErrorCode.ConnectionFailed, "response") => " (server closed mid-handshake — rejected id or refused target)",
        (ProxyErrorCode.InvalidResponse, "response") => " (server answered with a malformed protocol header)",
        _ => ""
    };

    private static TException? Inner<TException>(Exception ex) where TException : Exception
    {
        for (Exception? current = ex; current is not null; current = current.InnerException)
            if (current is TException match)
                return match;
        return null;
    }

    /// <summary>First sentence of a BCL message, scrubbed of this node's own values.</summary>
    private static string Detail(Exception ex, LiveNode node)
    {
        string message = ex.Message.ReplaceLineEndings(" ").Trim();
        if (message.Length > 160)
            message = message[..160] + "…";
        return Redactor.Scrub(message, node.Secrets);
    }
}

/// <summary>Accumulates live-probe results and renders the report.</summary>
internal sealed class LiveRun
{
    private readonly ProtocolStats _vless = new("vless", "successful nodes by mode", null);
    private readonly ProtocolStats _trojan = new("trojan", "successful nodes by mode", null);
    private readonly ProtocolStats _vmess = new("vmess", "successful nodes by mode", null);
    private readonly ProtocolStats _shadowsocks = new("ss", "successful nodes by mode", null);

    private ProtocolStats[] All => [_vless, _trojan, _vmess, _shadowsocks];

    public void Record(LiveNode node, LiveResult result)
    {
        var stats = node.Protocol switch
        {
            "vless" => _vless,
            "trojan" => _trojan,
            "ss" => _shadowsocks,
            _ => _vmess
        };

        if (result.Ok)
            stats.RecordOk($"{node.Mode}, {result.Detail}");
        else
            stats.RecordFailure(result.Detail, node.Shape, static shape => shape);
    }

    public string BuildReport(string corpusPath, LiveSample sample, int requested, int seed, TimeSpan timeout)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# QuickProxyNet live-node probe");
        sb.AppendLine();
        sb.AppendLine($"- Corpus: `{corpusPath}`");
        sb.AppendLine($"- Date: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC");
        sb.AppendLine($"- Sample: {sample.Nodes.Count} node(s) requested {requested}, seed {seed} (re-run with `--seed {seed}` to repeat)");
        sb.AppendLine($"- Dialled sequentially, {timeout.TotalSeconds:0.#}s budget per node, one request each");
        sb.AppendLine($"- Target through the tunnel: `http://{LiveProber.TargetHost}{LiveProber.TargetPath}` (expects `204`)");
        sb.AppendLine();
        sb.AppendLine("A node counts as a success only when a well-formed HTTP status line came back");
        sb.AppendLine("through the tunnel: VLESS and VMess validate their response header on the first");
        sb.AppendLine("read, so a returned stream on its own proves nothing.");
        sb.AppendLine();

        sb.AppendLine("## Result");
        sb.AppendLine();
        sb.AppendLine("| Protocol | Attempted | Succeeded | Failed | OK % |");
        sb.AppendLine("| --- | ---: | ---: | ---: | ---: |");
        foreach (var stats in All)
            sb.AppendLine(
                $"| {stats.Name} | {stats.Total} | {stats.Ok} | {stats.Failed} | " +
                $"{(stats.Total == 0 ? 0 : 100.0 * stats.Ok / stats.Total):F1}% |");
        sb.AppendLine();

        sb.AppendLine("## Eligible pool (before sampling)");
        sb.AppendLine();
        sb.AppendLine("Only configurations this library can speak are sampled — dialling a node we are");
        sb.AppendLine("guaranteed to reject measures nothing.");
        sb.AppendLine();
        sb.AppendLine("| Protocol | Lines in corpus | Connectable | Sampled |");
        sb.AppendLine("| --- | ---: | ---: | ---: |");
        foreach (var stats in All)
        {
            var pool = sample.Pools[stats.Name];
            sb.AppendLine($"| {stats.Name} | {pool.Seen} | {pool.Eligible.Count} | {stats.Total} |");
        }
        sb.AppendLine();

        foreach (var stats in All)
        {
            var pool = sample.Pools[stats.Name];
            if (pool.Exclusions.Count == 0)
                continue;
            sb.AppendLine($"### {stats.Name}: excluded from the pool");
            sb.AppendLine();
            foreach (var (reason, count) in pool.Exclusions.OrderByDescending(kv => kv.Value))
                sb.AppendLine($"- {reason} — {count}");
            sb.AppendLine();
        }

        foreach (var stats in All)
            stats.AppendBreakdown(sb);

        foreach (var stats in All)
            stats.AppendFailures(sb);

        return sb.ToString();
    }
}
