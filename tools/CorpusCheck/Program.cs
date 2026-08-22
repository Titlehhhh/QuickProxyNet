// CorpusCheck — one-shot diagnostic that runs QuickProxyNet's share-link parsers over a
// large corpus of real-world proxy share links and reports parse rates plus failures
// grouped by reason.
//
// A second, opt-in mode (`--live [N]`) dials a small SAMPLE of nodes from the "Checked"
// corpus and tunnels one HTTP request through each, to see whether the clients — not just
// the parsers — work against real servers. See LiveProbe.cs for the rules that mode obeys;
// it is manual-only and refuses to run under CI.
//
// Everything downloaded and everything written lives OUTSIDE the repository, in
// Path.GetTempPath()/QuickProxyNet-CorpusCheck. No corpus data may land in the repo.
//
// All example links in the report are REDACTED: these are real servers belonging to other
// people, so no output line may ever contain a usable credential (uuid/password), host,
// SNI, path or remark. See Redactor below.

using System.Text;
using System.Text.Json;
using QuickProxyNet;

namespace CorpusCheck;

internal static class Program
{
    private const string CorpusUrl =
        "https://raw.githubusercontent.com/heops6767/PypsCFG/main/output/merged_all.txt";

    /// <summary>
    /// Sibling of <see cref="CorpusUrl"/> with unreachable nodes already filtered out — the
    /// only sensible input for <c>--live</c>.
    /// </summary>
    private const string CheckedCorpusUrl =
        "https://raw.githubusercontent.com/heops6767/PypsCFG/main/output/merged_all_Checked.txt";

    private const int DefaultLiveCount = 30;

    /// <summary>
    /// Hard ceiling on <c>--live N</c>. This mode exists to diagnose our client against a
    /// handful of real servers; anything bigger is a scan of other people's infrastructure.
    /// </summary>
    private const int MaxSampleSize = 100;

    private const string Usage = """
        usage:
          CorpusCheck [--refresh] [--file <path>]
              Parse mode (default): runs the share-link parsers over merged_all.txt and
              reports parse rates with failures grouped by reason.

          CorpusCheck --live [N] [--refresh] [--file <path>] [--seed <n>] [--timeout <seconds>]
              Live mode (MANUAL ONLY): samples N connectable nodes (default 30, max 100)
              from merged_all_Checked.txt, dials each sequentially through this library and
              tunnels one HTTP request to a neutral connectivity endpoint.

        options:
          --refresh          re-download the corpus instead of using the temp-dir cache
          --file <path>      use a local corpus file instead of downloading
          --seed <n>         RNG seed for the live sample (reported, so a run repeats)
          --timeout <sec>    per-node budget in live mode (default 5)
        """;

    private static async Task<int> Main(string[] args)
    {
        bool refresh = false;
        bool live = false;
        string? localFile = null;
        int liveCount = DefaultLiveCount;
        int seed = Random.Shared.Next();
        double timeoutSeconds = 5;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--refresh":
                    refresh = true;
                    break;
                case "--file" when i + 1 < args.Length:
                    localFile = args[++i];
                    break;
                case "--live":
                    live = true;
                    // N is optional: "--live" and "--live 20" are both valid.
                    if (i + 1 < args.Length && int.TryParse(args[i + 1], out int parsedCount))
                    {
                        liveCount = parsedCount;
                        i++;
                    }
                    break;
                case "--seed" when i + 1 < args.Length && int.TryParse(args[i + 1], out int parsedSeed):
                    seed = parsedSeed;
                    i++;
                    break;
                case "--timeout" when i + 1 < args.Length && double.TryParse(args[i + 1], out double parsedTimeout):
                    timeoutSeconds = parsedTimeout;
                    i++;
                    break;
                case "--help" or "-h":
                    Console.WriteLine(Usage);
                    return 0;
                default:
                    Console.Error.WriteLine($"Unknown or malformed argument '{args[i]}'. Try --help.");
                    return 2;
            }
        }

        if (live)
        {
            if (liveCount is < 1 or > MaxSampleSize)
            {
                Console.Error.WriteLine(
                    $"--live N must be between 1 and {MaxSampleSize}. This is a diagnostic sample, not a sweep.");
                return 2;
            }
            if (timeoutSeconds is < 1 or > 30)
            {
                Console.Error.WriteLine("--timeout must be between 1 and 30 seconds.");
                return 2;
            }
            if (DetectCi() is { } ciVariable)
            {
                Console.Error.WriteLine(
                    $"Refusing to run --live: environment variable '{ciVariable}' indicates CI. " +
                    "This mode opens connections to third-party servers and is manual-only.");
                return 2;
            }
        }

        string tempDir = Path.Combine(Path.GetTempPath(), "QuickProxyNet-CorpusCheck");
        Directory.CreateDirectory(tempDir);

        string corpusPath;
        if (localFile is not null)
        {
            if (!File.Exists(localFile))
            {
                Console.Error.WriteLine($"File not found: {localFile}");
                return 2;
            }
            corpusPath = localFile;
        }
        else
        {
            corpusPath = await EnsureCorpusAsync(
                tempDir,
                live ? "merged_all_Checked.txt" : "merged_all.txt",
                live ? CheckedCorpusUrl : CorpusUrl,
                refresh);
        }

        return live
            ? await RunLiveAsync(corpusPath, tempDir, liveCount, seed, TimeSpan.FromSeconds(timeoutSeconds))
            : await RunParseAsync(corpusPath, tempDir);
    }

    /// <summary>Downloads the corpus into the temp dir unless a usable cache is already there.</summary>
    private static async Task<string> EnsureCorpusAsync(string tempDir, string fileName, string url, bool refresh)
    {
        string path = Path.Combine(tempDir, fileName);
        if (refresh || !File.Exists(path))
        {
            Console.WriteLine($"Downloading corpus from {url} ...");
            using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
            string text = await http.GetStringAsync(url);
            await File.WriteAllTextAsync(path, text);
            Console.WriteLine($"Cached at {path}");
        }
        else
        {
            Console.WriteLine($"Using cached corpus at {path} (use --refresh to re-download)");
        }
        return path;
    }

    private static async Task<int> RunParseAsync(string corpusPath, string tempDir)
    {
        var run = new CorpusRun();
        foreach (string rawLine in File.ReadLines(corpusPath))
        {
            string line = rawLine.Trim();
            if (line.Length == 0)
                continue;
            run.Process(line);
        }

        string report = run.BuildReport(corpusPath);
        Console.WriteLine();
        Console.WriteLine(report);

        string reportPath = Path.Combine(tempDir, "CorpusCheck-report.md");
        await File.WriteAllTextAsync(reportPath, report);
        Console.WriteLine($"Report written to {reportPath}");
        return 0;
    }

    private static async Task<int> RunLiveAsync(
        string corpusPath, string tempDir, int count, int seed, TimeSpan timeout)
    {
        var sample = LiveSampler.Build(corpusPath, count, seed);
        if (sample.Nodes.Count == 0)
        {
            Console.Error.WriteLine("No connectable nodes found in the corpus — nothing to probe.");
            return 1;
        }

        Console.WriteLine(
            $"Probing {sample.Nodes.Count} node(s) sequentially, {timeout.TotalSeconds:0.#}s each, seed {seed}.");
        Console.WriteLine(
            $"Target through each tunnel: http://{LiveProber.TargetHost}{LiveProber.TargetPath}");
        Console.WriteLine();

        // Ctrl+C stops the run and still prints what was collected.
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        var prober = new LiveProber(timeout);
        var run = new LiveRun();

        int index = 0;
        foreach (var node in sample.Nodes)
        {
            if (cts.IsCancellationRequested)
            {
                Console.WriteLine("Cancelled — reporting what was collected so far.");
                break;
            }

            index++;
            var result = await prober.ProbeAsync(node, cts.Token);
            run.Record(node, result);
            Console.WriteLine(
                $"[{index,3}/{sample.Nodes.Count}] {(result.Ok ? "ok  " : "FAIL")} " +
                $"{node.Protocol,-6} {result.Elapsed.TotalSeconds,5:0.00}s  {result.Detail}");
        }

        string report = run.BuildReport(corpusPath, sample, count, seed, timeout);
        Console.WriteLine();
        Console.WriteLine(report);

        string reportPath = Path.Combine(tempDir, "CorpusCheck-live-report.md");
        await File.WriteAllTextAsync(reportPath, report);
        Console.WriteLine($"Report written to {reportPath}");
        return 0;
    }

    /// <summary>Returns the name of the CI variable that is set, or null when not on CI.</summary>
    private static string? DetectCi()
    {
        foreach (string name in new[] { "CI", "TF_BUILD", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL" })
            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name)))
                return name;
        return null;
    }
}

/// <summary>Accumulates per-protocol results for one pass over the corpus.</summary>
internal sealed class CorpusRun
{
    private static readonly string ParseNote =
        "(Parse success is not connect support — non-tcp transports and REALITY parse fine" +
        Environment.NewLine +
        "but throw NotSupportedException at connect time.)";

    private readonly ProtocolStats _vless = new("vless", breakdownNote: ParseNote);
    private readonly ProtocolStats _trojan = new("trojan", breakdownNote: ParseNote);
    private readonly ProtocolStats _vmess = new("vmess", breakdownNote: ParseNote);

    /// <summary>Schemes this library does not implement — reported, but not failures.</summary>
    private readonly SortedDictionary<string, int> _otherSchemes = new(StringComparer.OrdinalIgnoreCase);

    private int _noScheme;
    private int _total;

    public void Process(string line)
    {
        _total++;

        if (line.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
        {
            // Fast pass with TryParse; only failures pay for the exception below.
            if (VlessShareLink.TryParse(line, out var options))
            {
                _vless.RecordOk(VlessMode(options));
            }
            else
            {
                // TryParse discards the reason. Parse throws a FormatException whose
                // message IS the reason, so re-parse the failure to capture it. Exceptions
                // are slow, but this is a one-shot diagnostic over ~18k lines and only
                // failing lines take this path — an acceptable trade for not having to
                // change the library's public API.
                _vless.RecordFailure(CaptureReason(() => VlessShareLink.Parse(line)), line, Redactor.RedactUriLink);
            }
        }
        else if (line.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
        {
            if (TrojanShareLink.TryParse(line, out var options))
                _trojan.RecordOk($"transport={options.Transport.ToLowerInvariant()}");
            else
                _trojan.RecordFailure(CaptureReason(() => TrojanShareLink.Parse(line)), line, Redactor.RedactUriLink);
        }
        else if (line.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
        {
            if (VmessShareLink.TryParse(line, out var options))
                _vmess.RecordOk($"net={options.Transport.ToLowerInvariant()}, tls={(options.UseTls ? "on" : "off")}");
            else
                _vmess.RecordFailure(CaptureReason(() => VmessShareLink.Parse(line)), line, Redactor.RedactVmessLink);
        }
        else
        {
            int schemeEnd = line.IndexOf("://", StringComparison.Ordinal);
            if (schemeEnd > 0 && schemeEnd <= 16)
            {
                string scheme = line[..schemeEnd].ToLowerInvariant();
                _otherSchemes[scheme] = _otherSchemes.GetValueOrDefault(scheme) + 1;
            }
            else
            {
                _noScheme++;
            }
        }
    }

    private static string VlessMode(VlessOptions options)
    {
        string security = options.Security switch
        {
            VlessSecurity.Tls => "tls",
            VlessSecurity.Reality => "reality",
            _ => "none"
        };
        return $"transport={options.Transport.ToLowerInvariant()}, security={security}";
    }

    private static string CaptureReason(Action parse)
    {
        try
        {
            parse();
            // TryParse failed but Parse succeeded — should be impossible; make it visible.
            return "(inconsistent: TryParse failed but Parse succeeded)";
        }
        catch (FormatException ex)
        {
            return Redactor.NormalizeReason(ex.Message);
        }
        catch (Exception ex)
        {
            // Anything but FormatException escaping Parse is itself a finding.
            return $"(unexpected {ex.GetType().Name}) {Redactor.NormalizeReason(ex.Message)}";
        }
    }

    public string BuildReport(string corpusPath)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# QuickProxyNet share-link corpus check");
        sb.AppendLine();
        sb.AppendLine($"- Corpus: `{corpusPath}`");
        sb.AppendLine($"- Date: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC");
        sb.AppendLine($"- Non-empty lines: {_total}");
        sb.AppendLine();

        sb.AppendLine("## Parse rate");
        sb.AppendLine();
        sb.AppendLine("| Protocol | Total | Parsed OK | Failed | OK % |");
        sb.AppendLine("| --- | ---: | ---: | ---: | ---: |");
        foreach (var stats in new[] { _vless, _trojan, _vmess })
        {
            sb.AppendLine(
                $"| {stats.Name} | {stats.Total} | {stats.Ok} | {stats.Failed} | " +
                $"{(stats.Total == 0 ? 0 : 100.0 * stats.Ok / stats.Total):F1}% |");
        }
        sb.AppendLine();

        if (_otherSchemes.Count > 0 || _noScheme > 0)
        {
            sb.AppendLine("## Other schemes (not implemented by this library — not failures)");
            sb.AppendLine();
            foreach (var (scheme, count) in _otherSchemes.OrderByDescending(kv => kv.Value))
                sb.AppendLine($"- `{scheme}://` — {count}");
            if (_noScheme > 0)
                sb.AppendLine($"- (no recognizable scheme) — {_noScheme}");
            sb.AppendLine();
        }

        foreach (var stats in new[] { _vless, _trojan, _vmess })
            stats.AppendBreakdown(sb);

        foreach (var stats in new[] { _vless, _trojan, _vmess })
            stats.AppendFailures(sb);

        return sb.ToString();
    }
}

/// <summary>
/// Per-protocol counters, an OK-mode breakdown and failure groups. Shared by the parse
/// report and the <c>--live</c> report, which differ only in the breakdown wording.
/// </summary>
internal sealed class ProtocolStats(
    string name,
    string breakdownHeading = "parsed-OK breakdown by mode",
    string? breakdownNote = null)
{
    private const int MaxExamplesPerGroup = 3;

    public string Name { get; } = name;
    public int Total { get; private set; }
    public int Ok { get; private set; }
    public int Failed { get; private set; }

    private readonly Dictionary<string, int> _okModes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, FailureGroup> _failures = new(StringComparer.Ordinal);

    public void RecordOk(string mode)
    {
        Total++;
        Ok++;
        _okModes[mode] = _okModes.GetValueOrDefault(mode) + 1;
    }

    public void RecordFailure(string reason, string link, Func<string, string> redact)
    {
        Total++;
        Failed++;

        if (!_failures.TryGetValue(reason, out var group))
            _failures[reason] = group = new FailureGroup();

        group.Count++;
        if (group.Examples.Count < MaxExamplesPerGroup)
        {
            string example = redact(link);
            // Keep examples within a group distinct — three identical shapes teach nothing.
            if (!group.Examples.Contains(example))
                group.Examples.Add(example);
        }
    }

    public void AppendBreakdown(StringBuilder sb)
    {
        if (Ok == 0)
            return;

        sb.AppendLine($"## {Name}: {breakdownHeading}");
        sb.AppendLine();
        if (breakdownNote is not null)
        {
            sb.AppendLine(breakdownNote);
            sb.AppendLine();
        }
        foreach (var (mode, count) in _okModes.OrderByDescending(kv => kv.Value))
            sb.AppendLine($"- {mode} — {count}");
        sb.AppendLine();
    }

    public void AppendFailures(StringBuilder sb)
    {
        if (Failed == 0)
            return;

        sb.AppendLine($"## {Name}: failures grouped by reason ({Failed} total)");
        sb.AppendLine();
        foreach (var (reason, group) in _failures.OrderByDescending(kv => kv.Value.Count))
        {
            sb.AppendLine($"### [{group.Count}x] {reason}");
            sb.AppendLine();
            foreach (string example in group.Examples)
                sb.AppendLine($"- `{example}`");
            sb.AppendLine();
        }
    }

    private sealed class FailureGroup
    {
        public int Count;
        public readonly List<string> Examples = new();
    }
}

/// <summary>
/// Credential redaction. These are REAL servers belonging to other people: no output may
/// contain a usable credential. Userinfo becomes <c>&lt;id&gt;</c>, the host becomes
/// <c>&lt;host&gt;</c>, fragments (remarks) are dropped, and query/JSON values are only
/// shown for a whitelist of mode-describing keys (type/security/fp/...). Everything else —
/// sni, path, pbk, sid, unknown keys — is masked, so an example identifies a SHAPE, never
/// a server.
/// </summary>
internal static class Redactor
{
    /// <summary>Query keys whose values describe a mode and identify no server.</summary>
    private static readonly HashSet<string> SafeQueryKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "type", "network", "security", "encryption", "flow", "fp", "alpn",
        "headerType", "mode", "allowInsecure", "insecure", "packetEncoding"
    };

    /// <summary>VMess JSON keys whose values are safe to show (never id/add/ps/host/sni/path).</summary>
    private static readonly HashSet<string> SafeVmessKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "v", "net", "tls", "type", "scy", "security", "aid", "alterId", "alpn"
    };

    /// <summary>
    /// Collapses variable content out of failure messages so identical problems group
    /// together, and strips the one secret a message can embed (the invalid user id).
    /// </summary>
    public static string NormalizeReason(string message)
    {
        // "... user id 'xxxx' is not a valid UUID." — the quoted value is the credential.
        // All other quoted values in parser messages are mode names (security, type, scy)
        // and are the interesting, non-secret part of the group key.
        if (message.Contains("user id", StringComparison.OrdinalIgnoreCase))
            return ReplaceQuoted(message, "<id>");
        return message;
    }

    /// <summary>
    /// Removes a specific node's own values from free text before it reaches the report.
    /// Used by <c>--live</c>, where a BCL exception message may quote the host or SNI it was
    /// talking to. Values shorter than three characters are skipped: they are not
    /// identifying on their own and blanket-replacing them would shred the message.
    /// </summary>
    public static string Scrub(string text, IReadOnlyList<string?> secrets)
    {
        foreach (string? secret in secrets)
        {
            if (string.IsNullOrEmpty(secret) || secret.Length < 3)
                continue;
            text = text.Replace(secret, "<redacted>", StringComparison.OrdinalIgnoreCase);
        }
        return text;
    }

    private static string ReplaceQuoted(string message, string placeholder)
    {
        int start = message.IndexOf('\'');
        int end = message.LastIndexOf('\'');
        if (start < 0 || end <= start)
            return message;
        return message[..(start + 1)] + placeholder + message[end..];
    }

    /// <summary>
    /// Redacts a vless:// or trojan:// link. Works on the raw string (not Uri) because
    /// many failing links are exactly the ones Uri cannot parse.
    /// </summary>
    public static string RedactUriLink(string link)
    {
        int schemeEnd = link.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd < 0)
            return "<unparseable line>";

        string scheme = link[..schemeEnd].ToLowerInvariant();
        string rest = link[(schemeEnd + 3)..];

        // Drop the fragment (remark) entirely — often a channel name, never needed.
        int hash = rest.IndexOf('#');
        if (hash >= 0)
            rest = rest[..hash];

        string authority = rest;
        string? query = null;
        int q = rest.IndexOf('?');
        if (q >= 0)
        {
            authority = rest[..q];
            query = rest[(q + 1)..];
        }

        // Split userinfo@hostport on the LAST '@' — passwords may contain '@'.
        string hostPort = authority;
        bool hasUserInfo = false;
        int at = authority.LastIndexOf('@');
        if (at >= 0)
        {
            hasUserInfo = at > 0;
            hostPort = authority[(at + 1)..];
        }

        // Keep the port (a port alone identifies nothing); mask the host. An IPv6 literal
        // is "[...]:port", so look for the port after the closing bracket.
        string port = "";
        int portSearchFrom = hostPort.StartsWith('[') ? hostPort.IndexOf(']') : 0;
        if (portSearchFrom >= 0)
        {
            int colon = hostPort.IndexOf(':', portSearchFrom);
            if (colon >= 0 && colon + 1 < hostPort.Length &&
                hostPort[(colon + 1)..].All(char.IsAsciiDigit))
            {
                port = ":" + hostPort[(colon + 1)..];
            }
        }
        bool ipv6 = hostPort.StartsWith('[');

        var sb = new StringBuilder();
        sb.Append(scheme).Append("://");
        if (hasUserInfo)
            sb.Append("<id>@");
        else if (at == 0)
            sb.Append("<empty-id>@");
        sb.Append(ipv6 ? "<ipv6-host>" : "<host>").Append(port);

        if (query is not null)
            sb.Append('?').Append(RedactQuery(query));

        return sb.ToString();
    }

    private static string RedactQuery(string query)
    {
        var sb = new StringBuilder();
        foreach (string pair in query.Split('&'))
        {
            if (sb.Length > 0)
                sb.Append('&');

            int eq = pair.IndexOf('=');
            if (eq < 0)
            {
                sb.Append(pair); // bare key, no value to leak
                continue;
            }

            string key = pair[..eq];
            string value = pair[(eq + 1)..];
            sb.Append(key).Append('=');
            if (value.Length == 0)
                sb.Append(""); // preserve the empty-value shape: "key="
            else if (SafeQueryKeys.Contains(key))
                sb.Append(Uri.UnescapeDataString(value));
            else
                sb.Append("<...>");
        }
        return sb.ToString();
    }

    /// <summary>
    /// Redacts a vmess:// link: decodes the base64 payload itself (tolerating the URL-safe
    /// alphabet and missing padding) and shows only JSON key names plus whitelisted
    /// non-secret values. Never id / add / ps / host / sni / path.
    /// </summary>
    public static string RedactVmessLink(string link)
    {
        string payload = link["vmess://".Length..].Trim();

        // v2rayN appends "#remark" AFTER the base64 payload, and the parser accepts that
        // form — so strip the fragment before decoding. Without this, a perfectly valid
        // payload was reported as "not decodable as base64" and the example described a
        // shape that does not exist. The base64 alphabet never contains '#', so cutting at
        // the first one cannot truncate real payload.
        int hash = payload.IndexOf('#');
        if (hash >= 0)
            payload = payload[..hash];

        // The other grammar in the wild is a plain URI: vmess://uuid@host:port?...#remark.
        // '@' is not in the base64 alphabet either, so its presence identifies that form
        // unambiguously — describe it as a URI rather than as undecodable base64.
        if (payload.Contains('@'))
            return RedactUriLink(link);

        byte[] bytes;
        try
        {
            string normalized = payload.Replace('-', '+').Replace('_', '/');
            normalized = string.Concat(normalized.Where(c => !char.IsWhiteSpace(c)));
            int pad = normalized.Length % 4;
            if (pad == 1)
                return DescribeUndecodable(payload);
            if (pad != 0)
                normalized += new string('=', 4 - pad);
            bytes = Convert.FromBase64String(normalized);
        }
        catch (FormatException)
        {
            return DescribeUndecodable(payload);
        }

        try
        {
            using var doc = JsonDocument.Parse(bytes);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return $"vmess://<payload decodes to JSON {doc.RootElement.ValueKind}, not an object>";

            var sb = new StringBuilder("vmess://{ ");
            bool first = true;
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                if (!first)
                    sb.Append(", ");
                first = false;

                sb.Append(property.Name).Append('=');
                if (SafeVmessKeys.Contains(property.Name))
                    sb.Append(property.Value.ValueKind == JsonValueKind.String
                        ? property.Value.GetString()
                        : property.Value.GetRawText());
                else
                    sb.Append("<...>");
            }
            sb.Append(" }");
            return sb.ToString();
        }
        catch (JsonException)
        {
            return $"vmess://<base64 decodes to non-JSON, {bytes.Length} bytes>";
        }
    }

    /// <summary>
    /// A payload that isn't base64 at all: describe its shape (length, offending character
    /// classes) without reproducing any of it.
    /// </summary>
    private static string DescribeUndecodable(string payload)
    {
        var offending = new SortedSet<string>();
        foreach (char c in payload)
        {
            if (char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '-' or '_' or '=')
                continue;
            offending.Add(c switch
            {
                '%' => "'%'",
                '@' => "'@'",
                '?' => "'?'",
                '#' => "'#'",
                ':' => "':'",
                '.' => "'.'",
                ',' => "','",
                _ when char.IsWhiteSpace(c) => "whitespace",
                _ when char.IsAscii(c) => "other ASCII punctuation",
                _ => "non-ASCII"
            });
        }

        string chars = offending.Count == 0
            ? $"valid alphabet but impossible length {payload.Length} % 4 == 1"
            : $"contains {string.Join(", ", offending)}";
        return $"vmess://<not decodable as base64: {payload.Length} chars, {chars}>";
    }
}
