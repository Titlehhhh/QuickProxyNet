using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace QuickProxyNet;

internal static class SocksHelper
{
    // One buffer holds every message this helper writes, so it is sized for the largest of them:
    //   SOCKS4a request  VN(1) CD(1) DSTPORT(2) DSTIP(4) USERID(255) NUL(1) HOST(255) NUL(1)  520
    //   SOCKS5 auth      VER(1) ULEN(1) UNAME(255) PLEN(1) PASSWD(255)                        513
    //   SOCKS4 request   VN(1) CD(1) DSTPORT(2) DSTIP(4) USERID(255) NUL(1)                   264
    //   SOCKS5 request   VER(1) CMD(1) RSV(1) ATYP(1) LEN(1) DST.ADDR(255) DST.PORT(2)        262
    //   SOCKS5 greeting  VER(1) NMETHODS(1) METHODS(2)                                          4
    // Replies are read into the same buffer and are smaller: at most 257 bytes in one read (the
    // rest of a SOCKS5 reply naming a domain), 8 for SOCKS4. It was 513, which a SOCKS4a request
    // with a long user id and host does not fit; ArrayPool rounding the rental up to 1024 is the
    // only reason that worked.
    internal const int BufferSize = 520;
    private const int ProtocolVersion4 = 4;
    private const int ProtocolVersion5 = 5;
    private const int SubnegotiationVersion = 1; // Socks5 username & password auth
    private const byte METHOD_NO_AUTH = 0;
    private const byte METHOD_USERNAME_PASSWORD = 2;
    private const byte CMD_CONNECT = 1;
    private const byte ATYP_IPV4 = 1;
    private const byte ATYP_DOMAIN_NAME = 3;
    private const byte ATYP_IPV6 = 4;
    private const byte Socks5_Success = 0;
    private const byte Socks4_Success = 90;
    private const byte Socks4_AuthFailed = 93;


    internal static async ValueTask EstablishSocks5TunnelAsync(Stream stream, string host, int port,
        NetworkCredential? credentials, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            // https://tools.ietf.org/html/rfc1928

            // +----+----------+----------+
            // |VER | NMETHODS | METHODS  |
            // +----+----------+----------+
            // | 1  |    1     | 1 to 255 |
            // +----+----------+----------+
            buffer[0] = ProtocolVersion5;
            if (credentials is null)
            {
                buffer[1] = 1;
                buffer[2] = METHOD_NO_AUTH;
            }
            else
            {
                buffer[1] = 2;
                buffer[2] = METHOD_NO_AUTH;
                buffer[3] = METHOD_USERNAME_PASSWORD;
            }

            await stream.WriteAsync(buffer.AsMemory(0, buffer[1] + 2), cancellationToken).ConfigureAwait(false);

            // +----+--------+
            // |VER | METHOD |
            // +----+--------+
            // | 1  |   1    |
            // +----+--------+
            await stream.ReadExactlyAsync(buffer.AsMemory(0, 2), cancellationToken).ConfigureAwait(false);
            VerifyProtocolVersion(ProtocolVersion5, buffer[0]);

            switch (buffer[1])
            {
                case METHOD_NO_AUTH:
                    // continue
                    break;

                case METHOD_USERNAME_PASSWORD:
                {
                    // https://tools.ietf.org/html/rfc1929
                    if (credentials is null)
                        // If the server is behaving well, it shouldn't pick username and password auth
                        // because we don't claim to support it when we don't have credentials.
                        // Just being defensive here.
                        throw new ProxyProtocolException(ProxyErrorCode.AuthRequired, "SOCKS server requested username & password authentication.");

                    // +----+------+----------+------+----------+
                    // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
                    // +----+------+----------+------+----------+
                    // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
                    // +----+------+----------+------+----------+
                    buffer[0] = SubnegotiationVersion;
                    var usernameLength = EncodeString(credentials.UserName, buffer.AsSpan(2),
                        nameof(credentials.UserName));
                    buffer[1] = usernameLength;
                    var passwordLength = EncodeString(credentials.Password, buffer.AsSpan(3 + usernameLength),
                        nameof(credentials.Password));
                    buffer[2 + usernameLength] = passwordLength;
                    await stream.WriteAsync(buffer.AsMemory(0, 3 + usernameLength + passwordLength), cancellationToken)
                        .ConfigureAwait(false);

                    // +----+--------+
                    // |VER | STATUS |
                    // +----+--------+
                    // | 1  |   1    |
                    // +----+--------+
                    await stream.ReadExactlyAsync(buffer.AsMemory(0, 2), cancellationToken).ConfigureAwait(false);
                    if (buffer[0] != SubnegotiationVersion)
                        throw new ProxyProtocolException(ProxyErrorCode.SocksUnexpectedVersion,
                            $"Unexpected SOCKS5 auth subnegotiation version. Expected {SubnegotiationVersion}, got {buffer[0]}.");
                    if (buffer[1] != Socks5_Success)
                        throw new ProxyProtocolException(ProxyErrorCode.AuthFailed, "Failed to authenticate with the SOCKS server.");
                    break;
                }

                default:
                    throw new ProxyProtocolException(ProxyErrorCode.SocksNoAuthMethod, "SOCKS server did not return a suitable authentication method.");
            }


            // +----+-----+-------+------+----------+----------+
            // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+
            buffer[0] = ProtocolVersion5;
            buffer[1] = CMD_CONNECT;
            buffer[2] = 0;
            int addressLength;

            if (IPAddress.TryParse(host, out var hostIP))
            {
                if (hostIP.AddressFamily == AddressFamily.InterNetwork)
                {
                    buffer[3] = ATYP_IPV4;
                    hostIP.TryWriteBytes(buffer.AsSpan(4), out var bytesWritten);
                    Debug.Assert(bytesWritten == 4);
                    addressLength = 4;
                }
                else
                {
                    Debug.Assert(hostIP.AddressFamily == AddressFamily.InterNetworkV6);
                    buffer[3] = ATYP_IPV6;
                    hostIP.TryWriteBytes(buffer.AsSpan(4), out var bytesWritten);
                    Debug.Assert(bytesWritten == 16);
                    addressLength = 16;
                }
            }
            else
            {
                buffer[3] = ATYP_DOMAIN_NAME;
                var hostLength = EncodeString(host, buffer.AsSpan(5), nameof(host));
                buffer[4] = hostLength;
                addressLength = hostLength + 1;
            }

            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(addressLength + 4), (ushort)port);

            await stream.WriteAsync(buffer.AsMemory(0, addressLength + 6), cancellationToken).ConfigureAwait(false);

            // +----+-----+-------+------+----------+----------+
            // |VER | REP |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+
            await stream.ReadExactlyAsync(buffer.AsMemory(0, 5), cancellationToken).ConfigureAwait(false);
            VerifyProtocolVersion(ProtocolVersion5, buffer[0]);
            if (buffer[1] != Socks5_Success)
                throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed,
                    $"SOCKS5 server rejected connection to {host}:{port} (reply code: 0x{buffer[1]:X2}).");
            var bytesToSkip = buffer[3] switch
            {
                ATYP_IPV4 => 5,
                ATYP_IPV6 => 17,
                ATYP_DOMAIN_NAME => buffer[4] + 2,
                _ => throw new ProxyProtocolException(ProxyErrorCode.SocksBadAddressType, "SOCKS server returned an unknown address type.")
            };
            await stream.ReadExactlyAsync(buffer.AsMemory(0, bytesToSkip), cancellationToken).ConfigureAwait(false);
            // response address not used
        }
        finally
        {
            // The request held the username and password (SOCKS5) or the user id (SOCKS4).
            ArrayPool<byte>.Shared.Return(buffer, clearArray: credentials is not null);
        }
    }

    internal static async ValueTask EstablishSocks4TunnelAsync(Stream stream, bool isVersion4a, string host, int port,
        NetworkCredential? credentials, CancellationToken cancellationToken)
    {
        // The client constructors have checked this already, but NetworkCredential is mutable, and a
        // user name changed after construction must not reach the wire either.
        ValidateUserId(credentials, nameof(credentials));

        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);

        try
        {
            // https://www.openssh.com/txt/socks4.protocol

            // +----+----+----+----+----+----+----+----+----+----+....+----+
            // | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
            // +----+----+----+----+----+----+----+----+----+----+....+----+
            //    1    1      2              4           variable       1
            buffer[0] = ProtocolVersion4;
            buffer[1] = CMD_CONNECT;

            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2), (ushort)port);

            IPAddress? ipv4Address = null;
            if (IPAddress.TryParse(host, out var hostIP))
            {
                if (hostIP.AddressFamily == AddressFamily.InterNetwork)
                    ipv4Address = hostIP;
                else if (hostIP.IsIPv4MappedToIPv6)
                    ipv4Address = hostIP.MapToIPv4();
                else
                    throw new ProxyProtocolException(ProxyErrorCode.SocksIPv6NotSupported, "SOCKS4 does not support IPv6 addresses.");
            }
            else if (!isVersion4a)
            {
                // Socks4 does not support domain names - try to resolve it here
                IPAddress[] addresses;
                try
                {
                    addresses =
                        await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cancellationToken)
                            .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    throw new ProxyProtocolException(ProxyErrorCode.SocksNoIPv4Address, "Failed to resolve the destination host to an IPv4 address.", ex);
                }

                if (addresses.Length == 0)
                    throw new ProxyProtocolException(ProxyErrorCode.SocksNoIPv4Address, "Failed to resolve the destination host to an IPv4 address.");

                ipv4Address = addresses[0];
            }

            if (ipv4Address is null)
            {
                Debug.Assert(isVersion4a);
                buffer[4] = 0;
                buffer[5] = 0;
                buffer[6] = 0;
                buffer[7] = 255;
            }
            else
            {
                ipv4Address.TryWriteBytes(buffer.AsSpan(4), out var bytesWritten);
                Debug.Assert(bytesWritten == 4);
            }

            var usernameLength = EncodeString(credentials?.UserName, buffer.AsSpan(8), nameof(credentials.UserName));
            buffer[8 + usernameLength] = 0;
            var totalLength = 9 + usernameLength;

            if (ipv4Address is null)
            {
                // https://www.openssh.com/txt/socks4a.protocol
                var hostLength = EncodeString(host, buffer.AsSpan(totalLength), nameof(host));
                buffer[totalLength + hostLength] = 0;
                totalLength += hostLength + 1;
            }

            // BufferSize is the largest SOCKS4a request, and ArrayPool's rounding would hide a request
            // that outgrew it.
            Debug.Assert(totalLength <= BufferSize);
            await stream.WriteAsync(buffer.AsMemory(0, totalLength), cancellationToken).ConfigureAwait(false);

            // +----+----+----+----+----+----+----+----+
            // | VN | CD | DSTPORT |      DSTIP        |
            // +----+----+----+----+----+----+----+----+
            //    1    1      2              4


            await stream.ReadExactlyAsync(buffer.AsMemory(0, 8), cancellationToken).ConfigureAwait(false);

            if (buffer[0] != 0)
                throw new ProxyProtocolException(ProxyErrorCode.SocksUnexpectedVersion,
                    $"Unexpected SOCKS4 reply version. Expected 0, got {buffer[0]}.");

            switch (buffer[1])
            {
                case Socks4_Success:
                    // Nothing to do
                    break;
                case Socks4_AuthFailed:
                    throw new ProxyProtocolException(ProxyErrorCode.AuthFailed, "Failed to authenticate with the SOCKS server.");
                default:
                    throw new ProxyProtocolException(ProxyErrorCode.ConnectionFailed, "SOCKS server failed to connect to the destination.");
            }
            // response address not used
        }
        finally
        {
            // The request held the username and password (SOCKS5) or the user id (SOCKS4).
            ArrayPool<byte>.Shared.Return(buffer, clearArray: credentials is not null);
        }
    }

    /// <summary>
    /// Refuses a SOCKS4 user id the wire format cannot carry: one with a NUL in it.
    /// </summary>
    /// <remarks>
    /// SOCKS4 ends the user id at its first NUL, and the proxy reads whatever follows as the next
    /// field. For SOCKS4a that is the host, so <c>alice\0evil.example</c> as the user id of a request
    /// for <c>good.example</c> reached the proxy as user <c>alice</c> asking for
    /// <c>evil.example</c>. The message never includes the user id, which is a credential.
    /// </remarks>
    internal static void ValidateUserId(NetworkCredential? credentials, string paramName)
    {
        if (credentials is not null && credentials.UserName.Contains('\0'))
            throw new ArgumentException(
                "A SOCKS4 user id cannot contain a NUL character: the protocol ends the user id at the " +
                "first one, and the proxy would read what follows as the next field.",
                paramName);
    }

    private static byte EncodeString(ReadOnlySpan<char> chars, Span<byte> buffer, string parameterName)
    {
        // The length goes out as a single byte, so the write is capped at 255 whatever room the
        // rented buffer has. ArrayPool rounds 520 up to 1024, and a string that fit the buffer but
        // not the length byte used to escape ConnectAsync as an OverflowException from the cast.
        if (!Encoding.UTF8.TryGetBytes(chars, buffer[..Math.Min(buffer.Length, 255)], out int written))
            throw new ProxyProtocolException(ProxyErrorCode.SocksStringTooLong,
                $"Encoding the {parameterName} took more than the maximum of 255 bytes");

        return (byte)written;
    }

    private static void VerifyProtocolVersion(byte expected, byte version)
    {
        if (expected != version)
            throw new ProxyProtocolException(ProxyErrorCode.SocksUnexpectedVersion,
                $"Unexpected SOCKS protocol version. Required {expected}, got {version}.");
    }


}
