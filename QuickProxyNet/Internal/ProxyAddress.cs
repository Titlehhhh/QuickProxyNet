using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace QuickProxyNet;

/// <summary>
/// Writes a target address in the SOCKS5-style <c>type + address</c> layout shared by
/// VLESS, VMess and Trojan. The numeric address-type codes differ between protocols
/// (VLESS uses 0x02 for domain, SOCKS5/Trojan use 0x03), so they are passed in by the
/// caller. Port is written separately because protocols disagree on its position.
/// </summary>
internal static class ProxyAddress
{
    /// <summary>Maximum bytes this writer can emit: type(1) + domain-len(1) + domain(255).</summary>
    public const int MaxLength = 1 + 1 + 255;

    /// <summary>
    /// Writes <c>atyp(1) + address(var)</c> for <paramref name="host"/> into
    /// <paramref name="dest"/> using the supplied type codes, and returns the number of
    /// bytes written. A literal IPv4/IPv6 host is emitted as raw address bytes; anything
    /// else is treated as a domain name with a single-byte length prefix.
    /// </summary>
    public static int WriteTypeAndAddress(
        string host, Span<byte> dest, byte ipv4Type, byte domainType, byte ipv6Type)
    {
        if (IPAddress.TryParse(host, out var ip))
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                dest[0] = ipv4Type;
                ip.TryWriteBytes(dest.Slice(1), out var n);
                Debug.Assert(n == 4);
                return 1 + 4;
            }

            Debug.Assert(ip.AddressFamily == AddressFamily.InterNetworkV6);
            dest[0] = ipv6Type;
            ip.TryWriteBytes(dest.Slice(1), out var n6);
            Debug.Assert(n6 == 16);
            return 1 + 16;
        }

        dest[0] = domainType;
        int len = EncodeDomain(host, dest.Slice(2));
        dest[1] = (byte)len;
        return 2 + len;
    }

    private static int EncodeDomain(ReadOnlySpan<char> host, Span<byte> dest)
    {
        // The domain length is a single byte, so cap the write at 256 to distinguish an
        // exactly-255-byte name from an overflow. UTF-8 is >= 1 byte/char, so a host with
        // more than 255 chars can never fit and is rejected without encoding.
        Span<byte> clamped = dest.Length > 256 ? dest.Slice(0, 256) : dest;
        if (host.Length > 255 || !Encoding.UTF8.TryGetBytes(host, clamped, out int n) || n > 255)
            throw new ProxyProtocolException(ProxyErrorCode.StringTooLong,
                "Target host name exceeds the maximum of 255 bytes.");
        return n;
    }
}
