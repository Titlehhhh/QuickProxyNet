using System.Buffers;
using System.Buffers.Binary;

namespace QuickProxyNet;

/// <summary>
/// Builds the VLESS request header and reads the VLESS response header over an already
/// established transport (plain TCP or an authenticated <see cref="System.Net.Security.SslStream"/>).
/// </summary>
/// <remarks>
/// Request layout (addons omitted for plain TCP):
/// <code>
/// ver(0x00) | uuid(16 BE) | addonsLen(0x00) | cmd(0x01 TCP) | port(2 BE) | atyp(1) | addr(var)
/// </code>
/// VLESS writes the port before the address (unlike SOCKS5) and uses 0x02 for a domain
/// address type. The response is <c>ver(1) + addonsLen(1) + addons(var)</c>, read in full
/// so the returned stream starts exactly at the target's first byte.
/// </remarks>
internal static class VlessHelper
{
    private const byte Version = 0x00;
    private const byte CommandTcp = 0x01;
    private const byte AtypIPv4 = 0x01;
    private const byte AtypDomain = 0x02;
    private const byte AtypIPv6 = 0x03;

    // ver(1) + uuid(16) + addonsLen(1) + cmd(1) + port(2) + max address.
    private const int MaxRequestSize = 1 + UuidCodec.Size + 1 + 1 + 2 + ProxyAddress.MaxLength;

    internal static async ValueTask EstablishVlessTunnelAsync(
        Stream stream, VlessOptions options, string host, int port, CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxRequestSize);
        try
        {
            int length = BuildRequest(buffer, options.Id, host, port);
            await stream.WriteAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);

            try
            {
                // Response header: ver(1) + addonsLen(1).
                await stream.ReadExactlyAsync(buffer.AsMemory(0, 2), cancellationToken).ConfigureAwait(false);
                if (buffer[0] != Version)
                    throw new ProxyProtocolException(ProxyErrorCode.InvalidResponse,
                        $"Unexpected VLESS response version. Expected 0x00, got 0x{buffer[0]:X2}.");

                // addonsLen is a single byte (<= 255 < buffer length), so the rented buffer
                // always holds it. Content is unused for plain TCP; draining it positions the
                // stream at the target's first response byte.
                int addonsLength = buffer[1];
                if (addonsLength > 0)
                    await stream.ReadExactlyAsync(buffer.AsMemory(0, addonsLength), cancellationToken)
                        .ConfigureAwait(false);
            }
            catch (EndOfStreamException ex)
            {
                // A short/closed response is the primary VLESS failure signal (e.g. wrong
                // UUID: many servers just drop the connection). Surface it like the HTTP path.
                throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                    $"VLESS server closed the connection before completing the handshake for {host}:{port} (wrong UUID or rejected request?).", ex);
            }
        }
        finally
        {
            // The buffer holds the user UUID (the VLESS credential); clear it before
            // returning the array to the shared pool.
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    internal static int BuildRequest(Span<byte> buffer, ReadOnlySpan<char> id, string host, int port)
    {
        buffer[0] = Version;
        UuidCodec.WriteBigEndian(id, buffer.Slice(1, UuidCodec.Size));
        buffer[17] = 0x00; // addons length
        buffer[18] = CommandTcp;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.Slice(19), (ushort)port);
        int addressLength =
            ProxyAddress.WriteTypeAndAddress(host, buffer.Slice(21), AtypIPv4, AtypDomain, AtypIPv6);
        return 21 + addressLength;
    }
}
