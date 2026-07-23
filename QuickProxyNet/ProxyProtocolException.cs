namespace QuickProxyNet;

/// <summary>
/// Represents an error that occurred during proxy protocol negotiation.
/// </summary>
public class ProxyProtocolException : Exception
{
    /// <summary>
    /// Gets the specific error code describing the failure reason.
    /// </summary>
    public ProxyErrorCode ErrorCode { get; }

    public ProxyProtocolException(ProxyErrorCode errorCode, string message, Exception innerException) : base(message, innerException)
    {
        ErrorCode = errorCode;
    }

    public ProxyProtocolException(ProxyErrorCode errorCode, string message) : base(message)
    {
        ErrorCode = errorCode;
    }

    public ProxyProtocolException(ProxyErrorCode errorCode)
    {
        ErrorCode = errorCode;
    }
}

/// <summary>
/// Describes the specific reason a proxy protocol operation failed.
/// </summary>
public enum ProxyErrorCode
{
    /// <summary>The proxy server requires authentication.</summary>
    AuthRequired,
    /// <summary>Authentication with the proxy server failed.</summary>
    AuthFailed,
    /// <summary>The proxy server failed to connect to the destination.</summary>
    ConnectionFailed,
    /// <summary>The proxy returned an invalid or unparseable response.</summary>
    InvalidResponse,
    /// <summary>A SOCKS string field exceeded the 255-byte limit.</summary>
    SocksStringTooLong,
    /// <summary>The SOCKS server returned an unexpected protocol version.</summary>
    SocksUnexpectedVersion,
    /// <summary>The SOCKS server did not offer a suitable authentication method.</summary>
    SocksNoAuthMethod,
    /// <summary>The SOCKS server returned an unknown address type.</summary>
    SocksBadAddressType,
    /// <summary>SOCKS4 does not support IPv6 addresses.</summary>
    SocksIPv6NotSupported,
    /// <summary>Failed to resolve host to an IPv4 address (required for SOCKS4).</summary>
    SocksNoIPv4Address,
    /// <summary>The proxy connection timed out.</summary>
    Timeout,
    /// <summary>A protocol string field (e.g. a target host name) exceeded the 255-byte limit.</summary>
    StringTooLong
}
