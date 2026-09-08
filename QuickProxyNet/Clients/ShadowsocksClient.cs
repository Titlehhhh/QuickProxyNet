using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace QuickProxyNet;

/// <summary>
/// Connects to a target host through a Shadowsocks proxy, speaking the AEAD construction of
/// SIP004/SIP007 over raw TCP with <c>aes-128-gcm</c>, <c>aes-192-gcm</c>, <c>aes-256-gcm</c> or
/// <c>chacha20-ietf-poly1305</c>.
/// </summary>
/// <remarks>
/// <para>
/// Everything else is refused by name with <see cref="NotSupportedException"/> at construction,
/// before any byte is written: the AEAD-2022 (<c>2022-blake3-*</c>, SIP022) family, every legacy
/// stream cipher, <c>none</c>/<c>plain</c>, <c>xchacha20-ietf-poly1305</c> (no XChaCha20 in the
/// .NET BCL), and any SIP003 <c>plugin=</c>. There is no TLS, no <c>ws</c>/<c>httpupgrade</c>
/// transport and no UDP in this protocol as spoken here. <c>chacha20-ietf-poly1305</c> also
/// requires an OS that provides ChaCha20-Poly1305 — on Windows that is build 20142 or later
/// (Windows 11 / Server 2022), never Windows 10.
/// </para>
/// <para>
/// <see cref="ConnectAsync(Stream, string, int, CancellationToken)"/> writes the salt and the
/// sealed target address and returns a <see cref="Stream"/> that seals everything written and
/// opens everything read. The server's salt is consumed lazily on the first <c>Read</c> — a real
/// server does not send it until the target has replied, so reading it at connect time would
/// deadlock every client-speaks-first protocol.
/// </para>
/// <para>
/// <b>A wrong password is not reported as one, by design of the protocol.</b> A Shadowsocks
/// server that cannot open the first chunk sends nothing and closes; Xray goes further and drains
/// a pseudo-random number of bytes first so the failure is not even timing-distinguishable. From
/// here that is a first <c>Read</c> failing with <see cref="ProxyProtocolException"/>
/// (<see cref="ProxyErrorCode.ConnectionFailed"/>) or timing out — exactly what a target the
/// server could not reach looks like. Nothing on the wire tells the two apart, so
/// <c>ConnectAsync</c> succeeds either way.
/// </para>
/// </remarks>
public sealed class ShadowsocksClient : ProxyClient
{
    private const byte AtypIPv4 = 0x01;
    private const byte AtypDomain = 0x03;
    private const byte AtypIPv6 = 0x04;

    /// <summary>atyp(1) + address(var) + port(2).</summary>
    private const int MaxAddressHeaderSize = ProxyAddress.MaxLength + 2;

    private readonly ShadowsocksMethod _method;

    /// <summary>Creates a Shadowsocks client from strongly-typed options.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> is null.</exception>
    /// <exception cref="ArgumentException">The password or the cipher name (<see cref="ShadowsocksOptions.Method"/>) is empty.</exception>
    /// <exception cref="NotSupportedException">
    /// The cipher is not one of the four this library speaks, a plugin is configured, or the
    /// platform does not provide the cipher. The message names what was found and what is accepted.
    /// </exception>
    public ShadowsocksClient(ShadowsocksOptions options)
        : base("ss", (options ?? throw new ArgumentNullException(nameof(options))).Host, options.Port)
    {
        if (string.IsNullOrEmpty(options.Password))
            throw new ArgumentException("Shadowsocks password must not be empty.", nameof(options));

        // A missing required field is the caller's mistake (ArgumentException family), not a link
        // naming a cipher this library cannot speak. The share-link parser never lets one through.
        if (string.IsNullOrEmpty(options.Method))
            throw new ArgumentException("Shadowsocks cipher name (Method) must not be empty.", nameof(options));

        // Refuse by name before anything else happens; there is no cipher to fall back to.
        _method = ShadowsocksCipher.Resolve(options.Method);

        if (!string.IsNullOrEmpty(options.Plugin))
            throw new NotSupportedException(PluginMessage(options.Plugin));

        ShadowsocksCipher.EnsurePlatformSupport(_method);

        Options = options;
    }

    /// <summary>Creates a Shadowsocks client by parsing an <c>ss://</c> share link.</summary>
    /// <exception cref="FormatException">The link is malformed.</exception>
    /// <exception cref="NotSupportedException">The link names a cipher or plugin this library does not speak.</exception>
    public static ShadowsocksClient FromShareLink(string shareLink) => new(ShadowsocksShareLink.Parse(shareLink));

    /// <summary>The parsed Shadowsocks configuration this client connects with.</summary>
    public ShadowsocksOptions Options { get; }

    /// <inheritdoc />
    public override ProxyType Type => ProxyType.Shadowsocks;

    /// <summary>Fills a salt buffer. Test hook: production draws a fresh random salt per connection.</summary>
    internal delegate void SaltFiller(Span<byte> salt);

    /// <summary>
    /// Replaces the random salt source. Tests inject the fixed salt the pinned vectors were
    /// generated with; production leaves this <see langword="null"/>.
    /// </summary>
    internal SaltFiller? SaltSource { get; set; }

    /// <inheritdoc />
    public override async ValueTask<Stream> ConnectAsync(Stream stream, string host, int port,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);

        ShadowsocksStream tunnel = CreateTunnel(stream);
        try
        {
            byte[] header = ArrayPool<byte>.Shared.Rent(MaxAddressHeaderSize);
            try
            {
                int length = BuildAddressHeader(header, host, port);

                // salt ‖ chunk(atyp ‖ addr ‖ port), eagerly, in one write. Nothing is read here:
                // the server will not answer until the target does.
                await tunnel.WriteAsync(header.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
                await tunnel.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(header);
            }

            return tunnel;
        }
        catch
        {
            // Owns the transport too, so this unwinds the whole stack.
            await tunnel.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>
    /// Writes the SOCKS5-style target address — <c>atyp(1) ‖ addr ‖ port(2 BE)</c>, with
    /// <c>0x01</c> IPv4, <c>0x03</c> domain, <c>0x04</c> IPv6 and the port <em>after</em> the
    /// address — and returns the number of bytes written.
    /// </summary>
    internal static int BuildAddressHeader(Span<byte> buffer, string host, int port)
    {
        int length = ProxyAddress.WriteTypeAndAddress(host, buffer, AtypIPv4, AtypDomain, AtypIPv6);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(length), (ushort)port);
        return length + 2;
    }

    // Derives the master key and draws the salt on the stack, and keys the stream with them.
    // Synchronous because stackalloc cannot live across an await.
    private ShadowsocksStream CreateTunnel(Stream stream)
    {
        int keySize = ShadowsocksCipher.KeySize(_method);
        Span<byte> masterKey = stackalloc byte[ShadowsocksCipher.MaxKeySize];
        Span<byte> salt = stackalloc byte[ShadowsocksCipher.MaxKeySize];
        masterKey = masterKey.Slice(0, keySize);
        salt = salt.Slice(0, keySize);
        try
        {
            ShadowsocksCipher.DeriveMasterKey(Options.Password, masterKey);

            if (SaltSource is null)
                ShadowsocksCipher.FillSalt(salt);
            else
                SaltSource(salt);

            // The stream copies both; the local master key is zeroed below.
            return new ShadowsocksStream(stream, _method, masterKey, salt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(masterKey);
        }
    }

    private static string PluginMessage(string plugin)
    {
        // SIP003: "name;key=value;…" — the name is what the user recognises.
        int semicolon = plugin.IndexOf(';');
        string name = semicolon < 0 ? plugin : plugin.Substring(0, semicolon);
        return $"Shadowsocks plugin '{name}' is not supported: SIP003 plugins (obfs-local/simple-obfs, v2ray-plugin, " +
               "xray-plugin, kcptun, GoQuiet, Cloak, gost-plugin) are separate processes this library does not spawn, " +
               "and connecting without the plugin would send plain Shadowsocks to a server expecting an obfuscated " +
               "stream. Use a server reachable without a plugin.";
    }
}
