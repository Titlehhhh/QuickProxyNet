using System.Buffers;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace QuickProxyNet;

/// <summary>
/// The HTTP/1.1 <c>Upgrade</c> exchange shared by the <c>ws</c> and <c>httpupgrade</c>
/// transports.
/// </summary>
/// <remarks>
/// Both advertise <c>Upgrade: websocket</c> — that is what makes <c>httpupgrade</c> look
/// ordinary to a middlebox — but only the <c>ws</c> transport may send the
/// <c>Sec-WebSocket-*</c> headers.
/// <para>
/// Sending them on <c>httpupgrade</c> looks harmless and is not: sing-box routes any request
/// carrying <c>Sec-WebSocket-Key</c> to its WebSocket handler, which an httpupgrade inbound
/// does not have, and answers <b>404</b>. Xray accepts either form, so a single server would
/// have blessed the bug — it was caught by running both. Measured directly against
/// sing-box 1.13: the key alone triggers it, while <c>Sec-WebSocket-Version</c> on its own
/// still upgrades.
/// </para>
/// </remarks>
internal static class HttpUpgradeHandshake
{
    /// <summary>RFC 6455 section 1.3 — the constant the server mixes into the accept token.</summary>
    private static ReadOnlySpan<byte> WebSocketGuid => "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"u8;

    /// <summary>Length of base64(16 bytes) — the <c>Sec-WebSocket-Key</c>.</summary>
    private const int KeyBase64Length = 24;

    /// <summary>Length of base64(SHA-1) — the <c>Sec-WebSocket-Accept</c>.</summary>
    private const int AcceptBase64Length = 28;

    /// <summary>
    /// Performs the upgrade and returns the stream to continue on.
    /// </summary>
    /// <param name="stream">The already-connected (and, for TLS modes, already-encrypted) stream.</param>
    /// <param name="path">Request target, sent verbatim — including any query such as <c>?ed=2048</c>.</param>
    /// <param name="hostHeader">Value for the <c>Host</c> header.</param>
    /// <param name="webSocket">
    /// True for the <c>ws</c> transport: send the <c>Sec-WebSocket-*</c> headers and require the
    /// server to echo a matching <c>Sec-WebSocket-Accept</c>. False for <c>httpupgrade</c>,
    /// which must send neither (see the type remarks).
    /// </param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    public static async ValueTask<Stream> PerformAsync(
        Stream stream,
        string path,
        string hostHeader,
        bool webSocket,
        CancellationToken cancellationToken)
    {
        // The expected accept token is computed here, before the first await: a stackalloc'd
        // Span cannot live across one, and hoisting the raw key into the async state machine
        // to recompute it later would keep it alive for no reason.
        var (request, length, expectedAccept) = BuildRequest(path, hostHeader, webSocket);
        try
        {
            await stream.WriteAsync(request.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // The request carries no secret, but returning it cleared costs nothing here:
            // this runs once per connection, not on the data path.
            ArrayPool<byte>.Shared.Return(request, clearArray: true);
        }

        var parser = new HttpResponseParser();
        try
        {
            bool found;
            do
            {
                Memory<byte> memory = parser.GetMemory();
                int read = await stream.ReadAsync(memory, cancellationToken).ConfigureAwait(false);
                if (read <= 0)
                    throw new ProxyProtocolException(ProxyErrorCode.TransportUpgradeFailed,
                        "The proxy closed the connection during the HTTP upgrade handshake.");
                found = parser.Parse(read);
            } while (!found);

            int status = parser.GetStatusCode();
            if (status != 101)
            {
                throw new ProxyProtocolException(ProxyErrorCode.TransportUpgradeFailed,
                    status < 0
                        ? "The proxy returned a malformed HTTP response to the upgrade request."
                        : $"The proxy refused the HTTP upgrade with status {status} (expected 101). " +
                          "The configured path is the usual cause: a WebSocket server only upgrades " +
                          "on the exact path it was configured with.");
            }

            if (expectedAccept is not null)
                ValidateAccept(parser.Headers, expectedAccept);

            // The server may pipeline the first frames straight after the header block.
            return PrefixedStream.WrapIfNeeded(parser.OverreadBytes, stream);
        }
        finally
        {
            parser.Dispose();
        }
    }

    private static void ValidateAccept(ReadOnlySpan<byte> headers, ReadOnlySpan<byte> expected)
    {
        if (!TryGetHeaderValue(headers, "sec-websocket-accept"u8, out ReadOnlySpan<byte> actual))
            throw new ProxyProtocolException(ProxyErrorCode.TransportUpgradeFailed,
                "The proxy accepted the upgrade but sent no Sec-WebSocket-Accept header, so it is " +
                "not a WebSocket endpoint.");

        if (!actual.SequenceEqual(expected))
            throw new ProxyProtocolException(ProxyErrorCode.TransportUpgradeFailed,
                "The proxy's Sec-WebSocket-Accept did not match the challenge; the peer is not " +
                "speaking WebSocket (an intercepting middlebox is the usual cause).");
    }

    /// <summary>
    /// Finds a header value by ASCII case-insensitive name. <paramref name="name"/> must be
    /// lowercase.
    /// </summary>
    private static bool TryGetHeaderValue(
        ReadOnlySpan<byte> headers, ReadOnlySpan<byte> name, out ReadOnlySpan<byte> value)
    {
        // Skip the status line; header fields start after the first CRLF.
        int start = headers.IndexOf("\r\n"u8);
        if (start < 0)
        {
            value = default;
            return false;
        }
        headers = headers[(start + 2)..];

        while (!headers.IsEmpty)
        {
            int eol = headers.IndexOf("\r\n"u8);
            ReadOnlySpan<byte> line = eol < 0 ? headers : headers[..eol];
            headers = eol < 0 ? default : headers[(eol + 2)..];

            if (line.IsEmpty)
                break;

            int colon = line.IndexOf((byte)':');
            if (colon < 0 || colon != name.Length)
                continue;

            if (!EqualsIgnoreAsciiCase(line[..colon], name))
                continue;

            value = Trim(line[(colon + 1)..]);
            return true;
        }

        value = default;
        return false;
    }

    private static bool EqualsIgnoreAsciiCase(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> lowercase)
    {
        for (int i = 0; i < lowercase.Length; i++)
        {
            byte c = actual[i];
            if (c is >= (byte)'A' and <= (byte)'Z')
                c += 32;
            if (c != lowercase[i])
                return false;
        }
        return true;
    }

    private static ReadOnlySpan<byte> Trim(ReadOnlySpan<byte> value)
    {
        int start = 0;
        while (start < value.Length && (value[start] == (byte)' ' || value[start] == (byte)'\t'))
            start++;

        int end = value.Length;
        while (end > start && (value[end - 1] == (byte)' ' || value[end - 1] == (byte)'\t'))
            end--;

        return value[start..end];
    }

    /// <summary>
    /// Builds the upgrade request into a pooled buffer and, for a WebSocket handshake, the
    /// accept token the server must echo back.
    /// </summary>
    private static (byte[] buffer, int length, byte[]? expectedAccept) BuildRequest(
        string path, string hostHeader, bool webSocket)
    {
        // The challenge is 16 random bytes; the server must echo back base64(SHA1(key || GUID)).
        Span<byte> keyBytes = stackalloc byte[16];
        Span<byte> key = stackalloc byte[KeyBase64Length];
        byte[]? expectedAccept = null;

        if (webSocket)
        {
            RandomNumberGenerator.Fill(keyBytes);
            Base64.EncodeToUtf8(keyBytes, key, out _, out _);

            Span<byte> challenge = stackalloc byte[KeyBase64Length + 36];
            key.CopyTo(challenge);
            WebSocketGuid.CopyTo(challenge[KeyBase64Length..]);

            Span<byte> digest = stackalloc byte[20];
            // SHA-1 is not a security choice here: RFC 6455 fixes it as the handshake token, and
            // the token proves only that the peer parsed the request, never authenticity. TLS
            // provides whatever authenticity this connection has.
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
            SHA1.HashData(challenge, digest);
#pragma warning restore CA5350

            expectedAccept = new byte[AcceptBase64Length];
            Base64.EncodeToUtf8(digest, expectedAccept, out _, out _);
        }

        int size =
            4 + Encoding.UTF8.GetMaxByteCount(path.Length) + 11 +   // "GET " path " HTTP/1.1\r\n"
            6 + Encoding.UTF8.GetMaxByteCount(hostHeader.Length) + 2 +
            100 +                                                    // fixed headers below
            KeyBase64Length + 2;

        byte[] buffer = ArrayPool<byte>.Shared.Rent(size);
        int pos = 0;

        Write(buffer, ref pos, "GET "u8);
        pos += Encoding.UTF8.GetBytes(path, buffer.AsSpan(pos));
        Write(buffer, ref pos, " HTTP/1.1\r\nHost: "u8);
        pos += Encoding.UTF8.GetBytes(hostHeader, buffer.AsSpan(pos));
        Write(buffer, ref pos, "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"u8);

        if (webSocket)
        {
            Write(buffer, ref pos, "Sec-WebSocket-Key: "u8);
            Write(buffer, ref pos, key);
            Write(buffer, ref pos, "\r\nSec-WebSocket-Version: 13\r\n"u8);
        }

        Write(buffer, ref pos, "\r\n"u8);

        return (buffer, pos, expectedAccept);

        static void Write(byte[] buffer, ref int pos, ReadOnlySpan<byte> value)
        {
            value.CopyTo(buffer.AsSpan(pos));
            pos += value.Length;
        }
    }
}
