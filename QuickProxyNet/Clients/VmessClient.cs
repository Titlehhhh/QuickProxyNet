using System.Buffers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// Connects to a target host through a VMess proxy, speaking <b>VMessAEAD</b>
/// (<c>alterId = 0</c>) with an <c>aes-128-gcm</c> or <c>chacha20-poly1305</c> body cipher,
/// optionally inside TLS.
/// </summary>
/// <remarks>
/// <para>
/// Unlike VLESS and Trojan, VMess encrypts the payload as well as the header, so
/// <see cref="ConnectAsync(Stream, string, int, CancellationToken)"/> does not return the
/// transport — it returns a <see cref="VmessStream"/> that seals everything written and
/// opens everything read. Closing that stream emits the authenticated empty chunk that
/// signals end-of-stream in band.
/// </para>
/// <para>
/// The <c>tcp</c>/<c>raw</c>, <c>ws</c> and <c>httpupgrade</c> transports are supported;
/// <c>grpc</c> and <c>h2</c> are rejected with <see cref="NotSupportedException"/> before
/// any bytes are written.
/// </para>
/// <para>
/// VMess is time-sensitive: the AuthID embeds the current UTC second and servers reject
/// anything more than ~120 s away from their own clock.
/// </para>
/// </remarks>
public sealed class VmessClient : ProxyClient
{
    /// <summary>
    /// The option bitflags sent in the request header — <b>S only</b>
    /// (<see cref="VmessRequest.OptionChunkStream"/>).
    /// </summary>
    /// <remarks>
    /// This is deliberately <b>not</b> <see cref="VmessRequest.DefaultOption"/> (<c>0x1D</c>
    /// = S|M|P|A). <see cref="VmessStream"/> implements the baseline body framing only: a
    /// plain <c>uint16</c> chunk length, no padding, no authenticated length. Announcing M
    /// (chunk masking) would make the server XOR every length with a SHAKE128 keystream,
    /// P would make it append random padding, and A would change the length encoding —
    /// each of which desynchronizes the reader immediately. The option byte must describe
    /// what this client can actually parse.
    /// </remarks>
    internal const byte RequestOption = VmessRequest.OptionChunkStream;

    // Layout of the session scratch buffer: the two request values then the two derived
    // response values, all 16 bytes.
    private const int RequestKeyOffset = 0;
    private const int RequestIvOffset = RequestKeyOffset + VmessRequest.BodyKeySize;
    private const int ResponseKeyOffset = RequestIvOffset + VmessRequest.BodyKeySize;
    private const int ResponseIvOffset = ResponseKeyOffset + VmessResponse.KeySize;
    private const int SessionSize = ResponseIvOffset + VmessResponse.KeySize;

    private readonly List<SslApplicationProtocol>? _alpn;

    /// <summary>Creates a VMess client from strongly-typed options.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// The options carry an invalid UUID or a non-zero <see cref="VmessOptions.AlterId"/>.
    /// </exception>
    public VmessClient(VmessOptions options)
        : base("vmess", (options ?? throw new ArgumentNullException(nameof(options))).Host, options.Port)
    {
        // Validate up front so a bad configuration fails at construction rather than
        // mid-connect (the share-link path already checked both, but a directly-built
        // VmessOptions may not have).
        // Must use the same rule as the wire encoder: Guid.TryParse alone would reject the
        // short non-UUID ids that UuidCodec — and Xray — map to a derived UUID.
        Span<byte> probe = stackalloc byte[UuidCodec.Size];
        if (!UuidCodec.TryWriteBigEndian(options.Id, probe))
            throw new ArgumentException(
                $"VMess user id is unusable ({options.Id.Length} characters): it is neither a canonical UUID nor " +
                "a string of 1..30 characters (which would be mapped to a UUID).",
                nameof(options));

        if (options.AlterId != 0)
            throw new ArgumentException(
                $"VMess alterId {options.AlterId} is not supported: only alterId 0 (VMessAEAD) is " +
                "implemented, and a non-zero value selects the legacy MD5 authentication format.",
                nameof(options));

        Options = options;
        _alpn = BuildAlpn(options.Alpn);
    }

    /// <summary>Creates a VMess client by parsing a <c>vmess://</c> share link.</summary>
    /// <exception cref="FormatException">The link is malformed.</exception>
    public static VmessClient FromShareLink(string shareLink) => new(VmessShareLink.Parse(shareLink));

    /// <summary>The parsed VMess configuration this client connects with.</summary>
    public VmessOptions Options { get; }

    /// <inheritdoc />
    public override ProxyType Type => ProxyType.Vmess;

    /// <summary>
    /// Overrides validation of the proxy server's TLS certificate (only used when
    /// <see cref="VmessOptions.UseTls"/> is true). Ignored when
    /// <see cref="VmessOptions.AllowInsecure"/> is true.
    /// </summary>
    public RemoteCertificateValidationCallback? ServerCertificateValidationCallback { get; set; }

    /// <summary>TLS protocol versions offered to the proxy. Defaults to TLS 1.2 and 1.3.</summary>
    public SslProtocols SslProtocols { get; set; } = SslProtocols.Tls12 | SslProtocols.Tls13;

    /// <summary>
    /// Performs the VMessAEAD handshake over <paramref name="stream"/> and returns the
    /// encrypted body stream for <paramref name="host"/>:<paramref name="port"/>.
    /// </summary>
    /// <remarks>
    /// Only the request header is written here. The server response header is verified
    /// lazily on the first read (see <see cref="VmessResponseStream"/>), because a real
    /// VMess server does not flush it until the target produces data — reading it eagerly
    /// would deadlock every client-speaks-first protocol.
    /// </remarks>
    /// <exception cref="NotSupportedException">
    /// The configured transport or body cipher is not supported.
    /// </exception>
    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        // Reject unsupported transports and ciphers before writing any bytes or starting TLS.
        VmessSecurity security = EnsureSupported(out TransportKind transportKind);

        // Each layer owns the one below it, so tracking the outermost stream is enough to
        // unwind the whole stack on failure.
        Stream layered = stream;
        try
        {
            if (Options.UseTls)
            {
                // SslStream(leaveInnerStreamOpen:false) disposes the inner stream too.
                var ssl = new SslStream(layered, leaveInnerStreamOpen: false);
                layered = ssl;
                await TlsHandshake.AuthenticateAsync(
                    ssl, BuildSslOptions(), Options.Sni ?? Options.Host, cancellationToken).ConfigureAwait(false);
            }

            layered = await ProxyTransport.ApplyAsync(
                transportKind,
                layered,
                Options.Path,
                ProxyTransport.ResolveHostHeader(Options.HostHeader, Options.Sni, Options.Host),
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await layered.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        byte[] request = ArrayPool<byte>.Shared.Rent(VmessRequest.MaxRequestSize);
        byte[] session = ArrayPool<byte>.Shared.Rent(SessionSize);
        try
        {
            int length = BuildHandshake(request, session, security, host, port, out byte responseVerifier);

            await layered.WriteAsync(request.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            await layered.FlushAsync(cancellationToken).ConfigureAwait(false);

            return CreateBodyStream(layered, session, responseVerifier, security);
        }
        catch
        {
            // Owns the TLS session and the transport layer as well. A half-built
            // VmessResponseStream holds no unmanaged state, so disposing the stack is
            // enough to release everything.
            await layered.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            // Both buffers held key material.
            ArrayPool<byte>.Shared.Return(request, clearArray: true);
            ArrayPool<byte>.Shared.Return(session, clearArray: true);
        }
    }

    /// <summary>
    /// Builds the sealed request header into <paramref name="request"/> and the four body
    /// key/IV values into <paramref name="session"/>, returning the header length.
    /// </summary>
    /// <remarks>
    /// Kept synchronous because <c>stackalloc</c> and <c>ref struct</c> locals cannot live
    /// across an <c>await</c>; the transient cmdKey and material scratch are zeroed here.
    /// </remarks>
    private int BuildHandshake(
        byte[] request, byte[] session, VmessSecurity security, string host, int port,
        out byte responseVerifier)
    {
        Span<byte> cmdKey = stackalloc byte[VmessCmdKey.Size];
        Span<byte> scratch = stackalloc byte[VmessRequest.MaterialScratchSize];
        try
        {
            VmessCmdKey.Derive(Options.Id, cmdKey);
            VmessRequestMaterial material = VmessRequest.CreateMaterial(scratch);

            int length = VmessRequest.Build(
                request, cmdKey, material, RequestOption, (byte)security, VmessRequest.CommandTcp, host, port);

            material.BodyKey.CopyTo(session.AsSpan(RequestKeyOffset, VmessRequest.BodyKeySize));
            material.BodyIv.CopyTo(session.AsSpan(RequestIvOffset, VmessRequest.BodyKeySize));

            // responseBodyKey/IV = SHA256(requestBodyKey/IV)[0:16].
            VmessResponse.DeriveBodyKeys(
                material.BodyKey,
                material.BodyIv,
                session.AsSpan(ResponseKeyOffset, VmessResponse.KeySize),
                session.AsSpan(ResponseIvOffset, VmessResponse.KeySize));

            responseVerifier = material.ResponseVerifier;
            return length;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(cmdKey);
            CryptographicOperations.ZeroMemory(scratch);
        }
    }

    /// <summary>
    /// Layers the response-header reader and the body cipher over the transport:
    /// <c>transport → VmessResponseStream → VmessStream</c>.
    /// </summary>
    private static Stream CreateBodyStream(
        Stream transport, byte[] session, byte responseVerifier, VmessSecurity security)
    {
        var deferred = new VmessResponseStream(
            transport,
            session.AsSpan(ResponseKeyOffset, VmessResponse.KeySize),
            session.AsSpan(ResponseIvOffset, VmessResponse.KeySize),
            responseVerifier);

        // Both constructors copy the key material out of the session buffer, so the caller
        // is free to clear and return it as soon as this returns.
        return new VmessStream(
            deferred,
            session.AsSpan(RequestKeyOffset, VmessRequest.BodyKeySize),
            session.AsSpan(RequestIvOffset, VmessRequest.BodyKeySize),
            session.AsSpan(ResponseKeyOffset, VmessResponse.KeySize),
            session.AsSpan(ResponseIvOffset, VmessResponse.KeySize),
            security);
    }

    /// <summary>
    /// Validates everything that cannot be expressed in the type system, and resolves the
    /// body cipher. Runs before any byte is written or any TLS handshake is started.
    /// </summary>
    private VmessSecurity EnsureSupported(out TransportKind transportKind)
    {
        transportKind = Options.TransportKind;
        if (transportKind == TransportKind.Unsupported)
            throw new NotSupportedException(
                $"VMess transport '{Options.Transport}' is not supported; 'tcp'/'raw', 'ws' and " +
                "'httpupgrade' are implemented.");

        VmessSecurity security = Options.ResolveSecurity();

        if (security == VmessSecurity.ChaCha20Poly1305 && !ChaCha20Poly1305.IsSupported)
            throw new NotSupportedException(
                "VMess security 'chacha20-poly1305' requires ChaCha20-Poly1305, which this platform " +
                "does not provide. Use 'aes-128-gcm' instead.");

        return security;
    }

    private SslClientAuthenticationOptions BuildSslOptions() => new()
    {
        // Same precedence Xray applies: explicit SNI, else the transport Host header, else the
        // server address. A ws+tls node commonly sets only 'host'.
        TargetHost = Options.Sni ?? Options.HostHeader ?? Options.Host,
        EnabledSslProtocols = SslProtocols,
        RemoteCertificateValidationCallback = Options.AllowInsecure
            ? static (_, _, _, _) => true
            : ServerCertificateValidationCallback,
        ApplicationProtocols = _alpn
    };

    // Built once per client from immutable options. Common ALPN ids map to the
    // allocation-free static instances instead of encoding a fresh byte[] each time.
    private static List<SslApplicationProtocol>? BuildAlpn(IReadOnlyList<string>? alpn)
    {
        if (alpn is not { Count: > 0 })
            return null;

        var list = new List<SslApplicationProtocol>(alpn.Count);
        for (int i = 0; i < alpn.Count; i++)
        {
            string p = alpn[i];
            list.Add(p switch
            {
                "h2" => SslApplicationProtocol.Http2,
                "http/1.1" => SslApplicationProtocol.Http11,
                "h3" => SslApplicationProtocol.Http3,
                _ => new SslApplicationProtocol(p)
            });
        }
        return list;
    }
}
