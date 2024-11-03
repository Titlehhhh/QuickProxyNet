﻿using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace QuickProxyNet;

internal static class ConnectHelper
{
    private static SslClientAuthenticationOptions SetUpRemoteCertificateValidationCallback(
        SslClientAuthenticationOptions sslOptions, HttpRequestMessage request)
    {
        // If there's a cert validation callback, and if it came from HttpClientHandler,
        // wrap the original delegate in order to change the sender to be the request message (expected by HttpClientHandler's delegate).
        var callback = sslOptions.RemoteCertificateValidationCallback;
        if (callback != null && callback.Target is CertificateCallbackMapper mapper)
        {
            sslOptions =
                sslOptions.ShallowClone(); // Clone as we're about to mutate it and don't want to affect the cached copy
            var localFromHttpClientHandler = mapper.FromHttpClientHandler;
            var localRequest = request;
            sslOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            {
                Debug.Assert(localRequest != null);
                var result = localFromHttpClientHandler(localRequest, certificate as X509Certificate2, chain,
                    sslPolicyErrors);
                localRequest =
                    null!; // ensure the SslOptions and this callback don't keep the first HttpRequestMessage alive indefinitely
                return result;
            };
        }

        return sslOptions;
    }

    public static async ValueTask<SslStream> EstablishSslConnectionAsync(SslClientAuthenticationOptions sslOptions,
        HttpRequestMessage request, bool async, Stream stream, CancellationToken cancellationToken)
    {
        sslOptions = SetUpRemoteCertificateValidationCallback(sslOptions, request);

        var sslStream = new SslStream(stream);

        try
        {
            if (async)
                await sslStream.AuthenticateAsClientAsync(sslOptions, cancellationToken).ConfigureAwait(false);
            else
                using (cancellationToken.UnsafeRegister(static s => ((Stream)s!).Dispose(), stream))
                {
                    sslStream.AuthenticateAsClient(sslOptions);
                }
        }
        catch (Exception e)
        {
            sslStream.Dispose();

            if (e is OperationCanceledException) throw;

            if (CancellationHelper.ShouldWrapInOperationCanceledException(e, cancellationToken))
                throw CancellationHelper.CreateOperationCanceledException(e, cancellationToken);

            //HttpRequestException ex = new HttpRequestException(HttpRequestError.SecureConnectionError, SR.net_http_ssl_connection_failed, e);

            throw;
        }

        // Handle race condition if cancellation happens after SSL auth completes but before the registration is disposed
        if (cancellationToken.IsCancellationRequested)
        {
            sslStream.Dispose();
            throw CancellationHelper.CreateOperationCanceledException(null, cancellationToken);
        }

        return sslStream;
    }

    /// <summary>
    ///     Helper type used by HttpClientHandler when wrapping SocketsHttpHandler to map its
    ///     certificate validation callback to the one used by SslStream.
    /// </summary>
    internal sealed class CertificateCallbackMapper
    {
        public readonly RemoteCertificateValidationCallback ForSocketsHttpHandler;

        public readonly Func<HttpRequestMessage, X509Certificate2?, X509Chain?, SslPolicyErrors, bool>
            FromHttpClientHandler;

        public CertificateCallbackMapper(
            Func<HttpRequestMessage, X509Certificate2?, X509Chain?, SslPolicyErrors, bool> fromHttpClientHandler)
        {
            FromHttpClientHandler = fromHttpClientHandler;
            ForSocketsHttpHandler = (sender, certificate, chain, sslPolicyErrors) =>
                FromHttpClientHandler((HttpRequestMessage)sender, certificate as X509Certificate2, chain,
                    sslPolicyErrors);
        }
    }

    //[SupportedOSPlatform("windows")]
    //[SupportedOSPlatform("linux")]
    //[SupportedOSPlatform("macos")]
    //public static async ValueTask<QuicConnection> ConnectQuicAsync(HttpRequestMessage request, DnsEndPoint endPoint, TimeSpan idleTimeout, SslClientAuthenticationOptions clientAuthenticationOptions, CancellationToken cancellationToken)
    //{
    //	clientAuthenticationOptions = SetUpRemoteCertificateValidationCallback(clientAuthenticationOptions, request);

    //	try
    //	{
    //		return await QuicConnection.ConnectAsync(new QuicClientConnectionOptions()
    //		{
    //			MaxInboundBidirectionalStreams = 0, // Client doesn't support inbound streams: https://www.rfc-editor.org/rfc/rfc9114.html#name-bidirectional-streams. An extension might change this.
    //			MaxInboundUnidirectionalStreams = 5, // Minimum is 3: https://www.rfc-editor.org/rfc/rfc9114.html#unidirectional-streams (1x control stream + 2x QPACK). Set to 100 if/when support for PUSH streams is added.
    //			IdleTimeout = idleTimeout,
    //			DefaultStreamErrorCode = (long)Http3ErrorCode.RequestCancelled,
    //			DefaultCloseErrorCode = (long)Http3ErrorCode.NoError,
    //			RemoteEndPoint = endPoint,
    //			ClientAuthenticationOptions = clientAuthenticationOptions
    //		}, cancellationToken).ConfigureAwait(false);
    //	}
    //	catch (Exception ex) when (ex is not OperationCanceledException)
    //	{
    //		throw;
    //		throw CreateWrappedException(ex, endPoint.Host, endPoint.Port, cancellationToken);
    //	}
    //}
}