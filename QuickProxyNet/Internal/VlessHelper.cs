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
/// address type. The response is <c>ver(1) + addonsLen(1) + addons(var)</c>; it is consumed
/// by <see cref="VlessResponseStream"/> on the first read — <b>not</b> here — because neither
/// Xray nor sing-box flushes it before the target replies. See that type for the measurement.
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

    /// <summary>
    /// Writes the VLESS request header over <paramref name="stream"/> and returns the stream
    /// the caller should use, which validates the server response header on its first read.
    /// </summary>
    /// <remarks>
    /// The response header is deliberately <b>not</b> read here. See
    /// <see cref="VlessResponseStream"/> for why reading it eagerly deadlocks against any
    /// client-speaks-first target.
    /// </remarks>
    internal static async ValueTask<Stream> EstablishVlessTunnelAsync(
        Stream stream, VlessOptions options, string host, int port, CancellationToken cancellationToken)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxRequestSize);
        try
        {
            int length = BuildRequest(buffer, options.Id, host, port);
            await stream.WriteAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // The buffer holds the user UUID (the VLESS credential); clear it before
            // returning the array to the shared pool.
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }

        return new VlessResponseStream(stream, host, port);
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
