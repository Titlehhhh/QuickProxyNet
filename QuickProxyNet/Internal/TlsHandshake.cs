using System.Net.Security;
using System.Security.Authentication;

namespace QuickProxyNet;

/// <summary>
/// Runs the client side of a TLS handshake and reports its failures as the library's own
/// exception type.
/// </summary>
/// <remarks>
/// <para>
/// This exists because <see cref="AuthenticationException"/> derives from
/// <see cref="SystemException"/>, not from <see cref="IOException"/> — so it slipped past the
/// <c>ex is IOException or SocketException</c> guard in <see cref="ProxyClient"/> and escaped
/// <c>ConnectAsync</c> raw. A caller that catches <see cref="ProxyProtocolException"/>, which is
/// the documented contract, therefore missed an expired certificate, a hostname the server will
/// not serve, or an absent shared cipher suite entirely: the three ways a TLS-carried node most
/// often dies.
/// </para>
/// <para>
/// It deliberately does not touch <see cref="IOException"/>. A truncated handshake is a transport
/// failure, and the layer above already has the context to name which peer dropped it.
/// </para>
/// </remarks>
internal static class TlsHandshake
{
    /// <summary>
    /// Performs <see cref="SslStream.AuthenticateAsClientAsync(SslClientAuthenticationOptions, CancellationToken)"/>,
    /// converting <see cref="AuthenticationException"/> into
    /// <see cref="ProxyErrorCode.TlsHandshakeFailed"/>.
    /// </summary>
    /// <param name="ssl">The stream to authenticate. The caller owns it and disposes it on failure.</param>
    /// <param name="options">The client authentication options.</param>
    /// <param name="peer">How to name the far side in the error message — an SNI or a host:port.</param>
    /// <param name="cancellationToken">A token to cancel the handshake.</param>
    public static async ValueTask AuthenticateAsync(
        SslStream ssl,
        SslClientAuthenticationOptions options,
        string peer,
        CancellationToken cancellationToken)
    {
        try
        {
            await ssl.AuthenticateAsClientAsync(options, cancellationToken).ConfigureAwait(false);
        }
        catch (AuthenticationException ex)
        {
            throw new ProxyProtocolException(
                ProxyErrorCode.TlsHandshakeFailed,
                $"TLS handshake with {peer} failed: {ex.Message}",
                ex);
        }
    }
}
