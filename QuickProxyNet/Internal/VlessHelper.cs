using System.Buffers;
using System.Buffers.Binary;
using System.Text;

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

    /// <summary>Protobuf tag for <c>Addons.Flow</c>: field 1, length-delimited.</summary>
    private const byte AddonsFlowTag = 0x0A;

    /// <summary>The tag and length that precede the flow identifier inside the addons block.</summary>
    private const int AddonsOverhead = 2;

    // ver(1) + uuid(16) + addonsLen(1) + addons + cmd(1) + port(2) + max address.
    private static readonly int MaxRequestSize =
        1 + UuidCodec.Size + 1 + AddonsOverhead + VisionStream.FlowName.Length + 1 + 2 + ProxyAddress.MaxLength;

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
        bool vision = IsVision(options.Flow);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxRequestSize);
        try
        {
            int length = BuildRequest(buffer, options.Id, host, port, vision ? VisionStream.FlowName : default);
            await stream.WriteAsync(buffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // The buffer holds the user UUID (the VLESS credential); clear it before
            // returning the array to the shared pool.
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }

        Stream session = new VlessResponseStream(stream, host, port);
        if (!vision)
            return session;

        // Vision framing starts where the payload would otherwise start, so it wraps the
        // response stream rather than the transport.
        return CreateVisionStream(session, options.Id);
    }

    /// <summary>
    /// Whether <paramref name="flow"/> is the one XTLS flow this library speaks.
    /// </summary>
    /// <remarks>
    /// The comparison is exact. A server configured with a flow we do not implement must fail
    /// loudly rather than be handed a plain VLESS request that it will answer in a framing we
    /// then misread — which looks like a working connection for about one packet.
    /// </remarks>
    internal static bool IsVision(string? flow) =>
        string.Equals(flow, VisionStream.FlowName, StringComparison.Ordinal);

    private static VisionStream CreateVisionStream(Stream session, string id)
    {
        Span<byte> uuid = stackalloc byte[UuidCodec.Size];
        UuidCodec.WriteBigEndian(id, uuid);
        return new VisionStream(session, uuid);
    }

    internal static int BuildRequest(Span<byte> buffer, ReadOnlySpan<char> id, string host, int port)
        => BuildRequest(buffer, id, host, port, default);

    /// <summary>
    /// Writes the request header, carrying <paramref name="flow"/> in the addons block when it
    /// is non-empty. The addons are a protobuf message with a single field, so the encoding is
    /// written by hand rather than pulling in a protobuf runtime for five bytes.
    /// </summary>
    internal static int BuildRequest(
        Span<byte> buffer, ReadOnlySpan<char> id, string host, int port, ReadOnlySpan<char> flow)
    {
        buffer[0] = Version;
        UuidCodec.WriteBigEndian(id, buffer.Slice(1, UuidCodec.Size));

        int offset = 1 + UuidCodec.Size;
        if (flow.IsEmpty)
        {
            buffer[offset++] = 0x00; // addons length
        }
        else
        {
            buffer[offset++] = (byte)(AddonsOverhead + flow.Length);
            buffer[offset++] = AddonsFlowTag;
            buffer[offset++] = (byte)flow.Length;
            offset += Encoding.ASCII.GetBytes(flow, buffer[offset..]);
        }

        buffer[offset++] = CommandTcp;
        BinaryPrimitives.WriteUInt16BigEndian(buffer[offset..], (ushort)port);
        offset += 2;
        offset += ProxyAddress.WriteTypeAndAddress(host, buffer[offset..], AtypIPv4, AtypDomain, AtypIPv6);
        return offset;
    }
}
