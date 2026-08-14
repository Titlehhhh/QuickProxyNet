using System.Net.WebSockets;

namespace QuickProxyNet;

/// <summary>
/// Presents an RFC 6455 client WebSocket as a byte <see cref="Stream"/>, which is what every
/// proxy protocol in this library expects to write its header into.
/// </summary>
/// <remarks>
/// The framing, masking and control-frame handling come from the BCL's <see cref="WebSocket"/>
/// (via <see cref="WebSocket.CreateFromStream(Stream, WebSocketCreationOptions)"/>) rather than
/// from hand-rolled code here. That implementation is hardened and allocation-tuned; a
/// from-scratch framer would be a large surface of subtle, security-relevant bugs (mask
/// reuse, fragment reassembly, control frames interleaved mid-message) for no gain.
/// <para>
/// Message boundaries are deliberately not preserved. A proxy tunnel is a byte stream: the
/// VLESS/VMess/Trojan header may land in one frame and the payload in another, and the server
/// concatenates them. Each <see cref="WriteAsync(ReadOnlyMemory{byte},CancellationToken)"/>
/// becomes exactly one binary frame, which is what Xray and sing-box do.
/// </para>
/// </remarks>
internal sealed class WebSocketStream : Stream
{
    private readonly WebSocket _webSocket;
    private readonly Stream _inner;
    private bool _receivedClose;

    public WebSocketStream(Stream inner)
    {
        _inner = inner;
        _webSocket = WebSocket.CreateFromStream(inner, new WebSocketCreationOptions
        {
            IsServer = false,
            // No keep-alive pings. A proxy tunnel is kept alive by the traffic on it, and an
            // unsolicited ping is one more thing distinguishing this client from a browser.
            KeepAliveInterval = TimeSpan.Zero
        });
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);

    public override async ValueTask<int> ReadAsync(
        Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_receivedClose || buffer.IsEmpty)
            return 0;

        // A zero-length binary frame is legal and carries no data. Returning its 0 verbatim
        // would tell the caller the stream ended, silently truncating the tunnel — so keep
        // receiving until there are actual bytes or the peer closes.
        while (true)
        {
            ValueWebSocketReceiveResult result;
            try
            {
                result = await _webSocket.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            }
            catch (WebSocketException ex)
            {
                throw new ProxyProtocolException(ProxyErrorCode.TransportUpgradeFailed,
                    $"The WebSocket transport failed while reading: {ex.Message}", ex);
            }

            if (result.MessageType == WebSocketMessageType.Close)
            {
                _receivedClose = true;
                return 0;
            }

            if (result.Count > 0)
                return result.Count;
        }
    }

    public override async ValueTask WriteAsync(
        ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        // Never emit an empty frame: it carries nothing and some servers treat it as a probe.
        if (buffer.IsEmpty)
            return;

        try
        {
            await _webSocket
                .SendAsync(buffer, WebSocketMessageType.Binary, endOfMessage: true, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (WebSocketException ex)
        {
            throw new ProxyProtocolException(ProxyErrorCode.TransportUpgradeFailed,
                $"The WebSocket transport failed while writing: {ex.Message}", ex);
        }
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override Task<int> ReadAsync(
        byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override Task WriteAsync(
        byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            // No closing handshake: it would need a round trip on a connection the caller is
            // already done with, and every real client just drops the socket.
            _webSocket.Abort();
            _webSocket.Dispose();

            // CreateFromStream hands stream ownership to the WebSocket, so this is normally
            // redundant — but Dispose is idempotent and leaking a socket is not worth the bet.
            _inner.Dispose();
        }
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        _webSocket.Abort();
        _webSocket.Dispose();
        await _inner.DisposeAsync().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }
}
