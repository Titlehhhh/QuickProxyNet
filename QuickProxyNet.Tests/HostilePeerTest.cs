using QuickProxyNet.Reality;

namespace QuickProxyNet.Tests;

/// <summary>
/// Drives the managed REALITY client against a peer that is malformed or actively hostile.
/// </summary>
/// <remarks>
/// <para>
/// Every other test of this code talks to a real, well-behaved Xray server. That proves
/// interoperability and proves nothing about what happens when the bytes on the wire are chosen
/// by an adversary — which is the only situation REALITY exists for. These tests fill that gap;
/// the record-injection case below is one that a cooperating server can never produce.
/// </para>
/// <para>
/// Everything runs in memory. No process, no socket, no timing.
/// </para>
/// </remarks>
public class HostilePeerTest
{
    private static readonly byte[] PublicKey = new byte[32];

    private static RealityTlsOptions Options() => new()
    {
        ServerName = "qpn.test",
        PublicKey = ServerPublicKey(),
        ShortId = "ab12"
    };

    /// <summary>A syntactically valid X25519 public key; the tests never get far enough to use it.</summary>
    private static byte[] ServerPublicKey()
    {
        byte[] key = new byte[32];
        key[0] = 9;
        return key;
    }

    private static byte[] Record(TlsContentTypeForTests type, ReadOnlySpan<byte> payload)
    {
        byte[] record = new byte[5 + payload.Length];
        record[0] = (byte)type;
        record[1] = 3;
        record[2] = 3;
        record[3] = (byte)(payload.Length >> 8);
        record[4] = (byte)payload.Length;
        payload.CopyTo(record.AsSpan(5));
        return record;
    }

    private enum TlsContentTypeForTests : byte
    {
        ChangeCipherSpec = 20,
        Handshake = 22,
        ApplicationData = 23
    }

    /// <summary>
    /// Builds a ServerHello handshake message, with every field overridable so a test can bend
    /// exactly one of them.
    /// </summary>
    private static byte[] ServerHello(
        ReadOnlySpan<byte> sessionIdEcho,
        ushort suite = 0x1301,
        byte compression = 0,
        bool supportedVersions = true,
        bool keyShare = true,
        ReadOnlySpan<byte> random = default)
    {
        var body = new List<byte> { 0x03, 0x03 };

        if (random.IsEmpty)
            body.AddRange(new byte[32]);
        else
            body.AddRange(random.ToArray());

        body.Add((byte)sessionIdEcho.Length);
        body.AddRange(sessionIdEcho.ToArray());
        body.Add((byte)(suite >> 8));
        body.Add((byte)suite);
        body.Add(compression);

        var extensions = new List<byte>();
        if (supportedVersions)
            extensions.AddRange(new byte[] { 0, 43, 0, 2, 0x03, 0x04 });

        if (keyShare)
        {
            extensions.AddRange(new byte[] { 0, 51, 0, 36, 0x00, 0x1D, 0x00, 0x20 });
            extensions.AddRange(new byte[32]);
        }

        body.Add((byte)(extensions.Count >> 8));
        body.Add((byte)extensions.Count);
        body.AddRange(extensions);

        byte[] message = new byte[4 + body.Count];
        message[0] = 2; // server_hello
        message[1] = (byte)(body.Count >> 16);
        message[2] = (byte)(body.Count >> 8);
        message[3] = (byte)body.Count;
        body.CopyTo(message, 4);

        return message;
    }

    private static async Task<RealityHandshakeException> ExpectRefusalAsync(Func<byte[], byte[]> respond)
    {
        await using var peer = new ScriptedPeer(respond);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        return await Assert.ThrowsAsync<RealityHandshakeException>(
            async () => await RealityTlsClient.HandshakeAsync(peer, Options(), timeout.Token));
    }

    /// <summary>
    /// The one a cooperating server cannot produce: application data injected before the server
    /// has any keys.
    /// </summary>
    /// <remarks>
    /// Such a record is returned by the record layer verbatim, because there is nothing to
    /// decrypt it with. Buffering it would place bytes chosen by whoever is on the path at the
    /// head of the tunnel, and the handshake would still complete — injected records never enter
    /// the transcript, so the server's Finished and the REALITY certificate HMAC both still
    /// verify. It must be refused outright.
    /// </remarks>
    [Fact]
    public async Task ApplicationDataBeforeKeys_IsRefused()
    {
        RealityHandshakeException ex = await ExpectRefusalAsync(clientHello =>
        {
            byte[] injected = Record(TlsContentTypeForTests.ApplicationData, "attacker-chosen"u8);
            byte[] hello = Record(
                TlsContentTypeForTests.Handshake,
                ServerHello(clientHello.AsSpan(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize)));

            return [.. injected, .. hello];
        });

        Assert.Contains("application data", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Unencrypted handshake bytes trailing the ServerHello would be handed out later as though
    /// they had been decrypted.
    /// </summary>
    [Fact]
    public async Task PlaintextHandshakeAfterServerHello_IsRefused()
    {
        RealityHandshakeException ex = await ExpectRefusalAsync(clientHello =>
        {
            byte[] hello = ServerHello(clientHello.AsSpan(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize));

            // A second, forged handshake message riding in the same plaintext record.
            byte[] forged = [8, 0, 0, 2, 0, 0]; // EncryptedExtensions, empty
            return Record(TlsContentTypeForTests.Handshake, [.. hello, .. forged]);
        });

        Assert.Contains("unencrypted", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// RFC 8446 §4.1.3 requires checking the echo. For REALITY it also detects a ClientHello
    /// that was altered in flight, since the session id is where the sealed blob lives.
    /// </summary>
    [Fact]
    public async Task WrongSessionIdEcho_IsRefused()
    {
        RealityHandshakeException ex = await ExpectRefusalAsync(_ =>
            Record(TlsContentTypeForTests.Handshake, ServerHello(new byte[32])));

        Assert.Contains("session id", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A truncated ServerHello must name the problem, not escape as an index error.</summary>
    [Theory]
    [InlineData(4)]   // header only
    [InlineData(20)]  // mid-random
    [InlineData(38)]  // exactly the version and random, nothing after
    [InlineData(39)]  // a session id length with no session id
    public async Task TruncatedServerHello_IsRefusedWithAReason(int keep)
    {
        RealityHandshakeException ex = await ExpectRefusalAsync(clientHello =>
        {
            byte[] hello = ServerHello(clientHello.AsSpan(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize));
            byte[] truncated = hello.AsSpan(0, Math.Min(keep, hello.Length)).ToArray();

            // Keep the declared length consistent so the reader accepts the message and then has
            // to cope with the body being short.
            if (truncated.Length >= 4)
            {
                int bodyLength = truncated.Length - 4;
                truncated[1] = (byte)(bodyLength >> 16);
                truncated[2] = (byte)(bodyLength >> 8);
                truncated[3] = (byte)bodyLength;
            }

            return Record(TlsContentTypeForTests.Handshake, truncated);
        });

        Assert.False(string.IsNullOrWhiteSpace(ex.Message));
    }

    [Fact]
    public async Task HelloRetryRequest_IsRefusedByName()
    {
        byte[] helloRetryRandom =
        [
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
        ];

        RealityHandshakeException ex = await ExpectRefusalAsync(clientHello => Record(
            TlsContentTypeForTests.Handshake,
            ServerHello(
                clientHello.AsSpan(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize),
                random: helloRetryRandom)));

        Assert.Contains("HelloRetryRequest", ex.Message);
    }

    [Fact]
    public async Task CompressionMethod_IsRefused()
    {
        RealityHandshakeException ex = await ExpectRefusalAsync(clientHello => Record(
            TlsContentTypeForTests.Handshake,
            ServerHello(clientHello.AsSpan(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize), compression: 1)));

        Assert.Contains("compression", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task UnofferedCipherSuite_IsRefused()
    {
        RealityHandshakeException ex = await ExpectRefusalAsync(clientHello => Record(
            TlsContentTypeForTests.Handshake,
            ServerHello(clientHello.AsSpan(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize), suite: 0x009C)));

        Assert.Contains("cipher suite", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MissingSupportedVersions_IsRefused()
    {
        RealityHandshakeException ex = await ExpectRefusalAsync(clientHello => Record(
            TlsContentTypeForTests.Handshake,
            ServerHello(
                clientHello.AsSpan(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize),
                supportedVersions: false)));

        Assert.Contains("TLS 1.3", ex.Message);
    }

    [Fact]
    public async Task MissingKeyShare_IsRefused()
    {
        RealityHandshakeException ex = await ExpectRefusalAsync(clientHello => Record(
            TlsContentTypeForTests.Handshake,
            ServerHello(
                clientHello.AsSpan(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize),
                keyShare: false)));

        Assert.Contains("key_share", ex.Message);
    }

    /// <summary>
    /// A peer that sends nothing but ChangeCipherSpec must not hold the handshake open forever.
    /// </summary>
    [Fact]
    public async Task ChangeCipherSpecFlood_IsRefused()
    {
        RealityHandshakeException ex = await ExpectRefusalAsync(_ =>
        {
            var flood = new List<byte>();
            for (int i = 0; i < 64; i++)
                flood.AddRange(Record(TlsContentTypeForTests.ChangeCipherSpec, [1]));

            return flood.ToArray();
        });

        Assert.Contains("ChangeCipherSpec", ex.Message);
    }

    /// <summary>A peer that hangs up mid-handshake must not be reported as anything else.</summary>
    [Fact]
    public async Task PeerThatSaysNothing_Fails()
    {
        await using var peer = new ScriptedPeer(_ => []);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await Assert.ThrowsAnyAsync<Exception>(
            async () => await RealityTlsClient.HandshakeAsync(peer, Options(), timeout.Token));
    }

    /// <summary>
    /// A transport that captures what the client writes and replays a scripted answer.
    /// </summary>
    /// <remarks>
    /// The answer is a function of the captured ClientHello so a test can echo the session id
    /// the client actually generated — it is random per connection, so it cannot be hard-coded.
    /// </remarks>
    private sealed class ScriptedPeer(Func<byte[], byte[]> respond) : Stream
    {
        private readonly MemoryStream _written = new();
        private byte[]? _response;
        private int _offset;

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _written.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_response is null)
            {
                // The client's first write is one record: five bytes of header, then the hello.
                byte[] written = _written.ToArray();
                _response = written.Length > 5 ? respond(written.AsSpan(5).ToArray()) : [];
            }

            int count = Math.Min(buffer.Length, _response.Length - _offset);
            if (count <= 0)
                return ValueTask.FromResult(0);

            _response.AsSpan(_offset, count).CopyTo(buffer.Span);
            _offset += count;

            return ValueTask.FromResult(count);
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override void Write(byte[] buffer, int offset, int count) =>
            _written.Write(buffer, offset, count);

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                _written.Dispose();

            base.Dispose(disposing);
        }
    }
}
