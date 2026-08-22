using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace QuickProxyNet;

/// <summary>
/// Builds and writes the Trojan request over an already-authenticated
/// <see cref="System.Net.Security.SslStream"/>.
/// </summary>
/// <remarks>
/// Wire layout:
/// <code>
/// hex(SHA224(password))(56) | CRLF | cmd(0x01) | atyp(1) | addr(var) | port(2 BE) | CRLF
/// </code>
/// Trojan uses SOCKS5-style address type codes (0x01 IPv4 / 0x03 domain / 0x04 IPv6) and,
/// unlike VLESS, writes the port after the address. Trojan has no success response: on
/// auth/connect failure the server silently closes or falls back to masquerade, so the
/// helper only writes the request and never reads a reply.
/// </remarks>
internal static class TrojanHelper
{
    private const byte CommandTcp = 0x01;
    private const byte AtypIPv4 = 0x01;
    private const byte AtypDomain = 0x03;
    private const byte AtypIPv6 = 0x04;
    private const byte CR = 0x0D;
    private const byte LF = 0x0A;

    // hex(56) + CRLF(2) + cmd(1) + address(var) + port(2) + CRLF(2).
    private const int MaxRequestSize = Sha224.HexSize + 2 + 1 + ProxyAddress.MaxLength + 2 + 2;

    // Passwords longer than this (in UTF-8 bytes) fall back to a pooled buffer; typical
    // passwords fit the stack buffer and stay allocation-free.
    private const int StackPasswordBytes = 256;

    internal static async ValueTask EstablishTrojanTunnelAsync(
        Stream stream, TrojanOptions options, string host, int port, CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxRequestSize);
        try
        {
            int length = BuildRequest(buffer, options.Password, host, port);
            await stream.WriteAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // The buffer holds hex(SHA224(password)) — in Trojan that hash IS the replayable
            // credential, so clear it before the array goes back to the shared pool.
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    /// <summary>
    /// Writes the full Trojan request for <paramref name="host"/>:<paramref name="port"/>
    /// into <paramref name="buffer"/> and returns the number of bytes written.
    /// </summary>
    internal static int BuildRequest(Span<byte> buffer, string password, string host, int port)
    {
        WritePasswordHash(password, buffer);
        buffer[Sha224.HexSize] = CR;
        buffer[Sha224.HexSize + 1] = LF;

        int offset = Sha224.HexSize + 2;
        buffer[offset] = CommandTcp;
        offset++;

        int addressLength =
            ProxyAddress.WriteTypeAndAddress(host, buffer.Slice(offset), AtypIPv4, AtypDomain, AtypIPv6);
        offset += addressLength;

        BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(offset), (ushort)port);
        offset += 2;

        buffer[offset] = CR;
        buffer[offset + 1] = LF;
        return offset + 2;
    }

    private static void WritePasswordHash(string password, Span<byte> destinationAscii)
    {
        int maxBytes = Encoding.UTF8.GetMaxByteCount(password.Length);
        byte[]? rented = maxBytes > StackPasswordBytes ? ArrayPool<byte>.Shared.Rent(maxBytes) : null;
        Span<byte> pwd = rented ?? stackalloc byte[StackPasswordBytes];
        int written = 0;
        try
        {
            written = Encoding.UTF8.GetBytes(password, pwd);
            Sha224.WriteHexLower(pwd.Slice(0, written), destinationAscii);
        }
        finally
        {
            // Zero the raw password bytes (stack or pooled) before releasing.
            CryptographicOperations.ZeroMemory(pwd.Slice(0, written));
            if (rented is not null)
                ArrayPool<byte>.Shared.Return(rented);
        }
    }
}
