using System.Formats.Asn1;
using System.Security.Cryptography;

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
        ReadOnlySpan<byte> random = default,
        byte[]? keyShareValue = null)
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
            extensions.AddRange(keyShareValue ?? new byte[32]);
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

    private static async Task<RealityHandshakeException> ExpectRefusalAsync(
        Func<byte[], byte[]> respond, RealityTlsOptions? options = null)
    {
        await using var peer = new ScriptedPeer(respond);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<RealityHandshakeException>(
            async () => await RealityTlsClient.HandshakeAsync(peer, options ?? Options(), timeout.Token));

        // Nothing a hostile peer does here is "we were not recognised": it is the peer breaking
        // the protocol, and the code must say so — AuthFailed is reserved for the decoy relay.
        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
        return ex;
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

    /// <summary>
    /// A peer that hangs up mid-handshake is reported as a proxy error with the connection-failed
    /// code and a hint — this is exactly what a REALITY server with no fallback does to a client
    /// it does not recognise, so "EndOfStreamException" would be the least useful possible answer.
    /// </summary>
    [Fact]
    public async Task PeerThatHangsUp_IsConnectionFailedWithAHint()
    {
        await using var peer = new ScriptedPeer(_ => []);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var ex = await Assert.ThrowsAsync<RealityHandshakeException>(
            async () => await RealityTlsClient.HandshakeAsync(peer, Options(), timeout.Token));

        Assert.Equal(ProxyErrorCode.ConnectionFailed, ex.ErrorCode);
        Assert.Contains("pbk", ex.Message);
        Assert.IsType<EndOfStreamException>(ex.InnerException);
    }

    /// <summary>
    /// RFC 8446 §5.1 forbids zero-length handshake records. One is harmless; a peer can send them
    /// forever, and each used to cost the client a loop iteration and nothing else.
    /// </summary>
    [Fact]
    public async Task EmptyHandshakeRecord_IsRefused()
    {
        RealityHandshakeException ex = await ExpectRefusalAsync(_ =>
            Record(TlsContentTypeForTests.Handshake, ReadOnlySpan<byte>.Empty));

        Assert.Contains("zero-length", ex.Message);
    }

    // ---- A peer that holds real keys ----

    /// <summary>How <see cref="KeyedServer"/> bends its flight, if at all.</summary>
    private enum Flight
    {
        /// <summary>A correct flight, then application data under the application keys.</summary>
        WellFormed,

        /// <summary>Application data under the handshake keys, between CertificateVerify and Finished.</summary>
        ApplicationDataBeforeFinished,

        /// <summary>A NewSessionTicket in the same handshake-key record as the Finished.</summary>
        HandshakeBytesAfterFinished
    }

    /// <summary>The application data a keyed server sends.</summary>
    private static ReadOnlySpan<byte> ServerGreeting => "sent by the server"u8;

    /// <summary>
    /// The control for the keyed tests: the same peer with nothing bent is accepted, and the
    /// application data it sends after its Finished, in the same burst, reaches the caller.
    /// </summary>
    /// <remarks>
    /// Without this, a refusal in a keyed test could be a mistake in the peer rather than the check
    /// under test. It is also the legitimate form of what
    /// <see cref="ApplicationDataUnderHandshakeKeys_IsRefused"/> sends.
    /// </remarks>
    [Fact]
    public async Task KeyedServer_WellFormedFlight_CompletesAndCarriesData()
    {
        (RealityTlsOptions options, Func<byte[], byte[]> respond) = KeyedServer(Flight.WellFormed);
        await using var peer = new ScriptedPeer(respond);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await using Stream tunnel = await RealityTlsClient.HandshakeAsync(peer, options, timeout.Token);

        byte[] received = new byte[64];
        int count = await tunnel.ReadAsync(received, timeout.Token);
        Assert.Equal(ServerGreeting.ToArray(), received[..count]);
    }

    /// <summary>
    /// Application data protected by the server's handshake keys, sent before its Finished. The
    /// keys are genuine, so this is the server itself breaking TLS 1.3, not an injection.
    /// </summary>
    /// <remarks>
    /// RFC 8446 §2: application data MUST NOT be sent before the Finished. Go's client answers it
    /// with unexpected_message from <c>readRecordOrCCS</c>. This client used to keep it and hand it
    /// to the caller as the first bytes of the tunnel.
    /// </remarks>
    [Fact]
    public async Task ApplicationDataUnderHandshakeKeys_IsRefused()
    {
        (RealityTlsOptions options, Func<byte[], byte[]> respond) = KeyedServer(Flight.ApplicationDataBeforeFinished);

        RealityHandshakeException ex = await ExpectRefusalAsync(respond, options);

        Assert.Contains("application data before its Finished", ex.Message);
    }

    /// <summary>
    /// A handshake message after the server's Finished in the same record, and so under the
    /// handshake keys, although reads switch to the application keys right after the Finished.
    /// </summary>
    /// <remarks>
    /// RFC 8446 §5.1: handshake messages MUST NOT span key changes, and a receiver that sees one
    /// MUST abort with unexpected_message. Go's client checks it in <c>setReadTrafficSecret</c>.
    /// This client checked only after the ServerHello, and dropped these bytes without a word.
    /// </remarks>
    [Fact]
    public async Task HandshakeBytesAfterFinishedInItsRecord_AreRefused()
    {
        (RealityTlsOptions options, Func<byte[], byte[]> respond) = KeyedServer(Flight.HandshakeBytesAfterFinished);

        RealityHandshakeException ex = await ExpectRefusalAsync(respond, options);

        Assert.Contains("record that carried its Finished", ex.Message);
    }

    /// <summary>
    /// A REALITY server for one connection: its own REALITY key pair, and a reply computed from the
    /// ClientHello the client actually sent.
    /// </summary>
    /// <remarks>
    /// Everything the client verifies is genuine: an X25519 exchange, the RFC 8446 key schedule, a
    /// certificate whose signature field is the HMAC of the REALITY auth key, and a Finished over
    /// the real transcript. So when a flight built here is refused, the bent part is the only thing
    /// left to refuse. The CertificateVerify signature is filler, because the client does not check
    /// it: the certificate HMAC subsumes it.
    /// </remarks>
    private static (RealityTlsOptions Options, Func<byte[], byte[]> Respond) KeyedServer(Flight flight)
    {
        byte[] realityPrivateKey = new byte[X25519.KeySize];
        byte[] realityPublicKey = new byte[X25519.KeySize];
        X25519.GenerateKeyPair(realityPrivateKey, realityPublicKey);

        RealityTlsOptions options = new()
        {
            ServerName = "qpn.test",
            PublicKey = realityPublicKey,
            ShortId = "ab12"
        };

        return (options, clientHello => KeyedFlight(clientHello, realityPrivateKey, flight));
    }

    private static byte[] KeyedFlight(byte[] clientHello, byte[] realityPrivateKey, Flight flight)
    {
        TlsCipherSuite suite = TlsCipherSuite.FromId(0x1301)!;
        HashAlgorithmName hash = suite.Hash;
        byte[] zeros = new byte[suite.HashLength];
        byte[] emptyHash = SHA256.HashData(ReadOnlySpan<byte>.Empty);

        byte[] clientKeyShare = ClientKeyShare(clientHello);
        byte[] ephemeralPrivateKey = new byte[X25519.KeySize];
        byte[] ephemeralPublicKey = new byte[X25519.KeySize];
        X25519.GenerateKeyPair(ephemeralPrivateKey, ephemeralPublicKey);

        byte[] serverHello = ServerHello(
            clientHello.AsSpan(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize),
            keyShareValue: ephemeralPublicKey);

        using IncrementalHash transcript = IncrementalHash.CreateHash(hash);
        transcript.AppendData(clientHello);
        transcript.AppendData(serverHello);

        // RFC 8446 §7.1, from the server's side of the same exchange.
        byte[] shared = new byte[X25519.KeySize];
        X25519.Agree(shared, ephemeralPrivateKey, clientKeyShare);

        byte[] early = new byte[suite.HashLength];
        byte[] derived = new byte[suite.HashLength];
        byte[] handshakeSecret = new byte[suite.HashLength];
        byte[] serverHandshakeTraffic = new byte[suite.HashLength];
        byte[] masterSecret = new byte[suite.HashLength];
        byte[] serverApplicationTraffic = new byte[suite.HashLength];

        TlsKeySchedule.Extract(hash, zeros, zeros, early);
        TlsKeySchedule.DeriveSecret(hash, early, "derived"u8, emptyHash, derived);
        TlsKeySchedule.Extract(hash, derived, shared, handshakeSecret);
        TlsKeySchedule.DeriveSecret(
            hash, handshakeSecret, "s hs traffic"u8, transcript.GetCurrentHash(), serverHandshakeTraffic);
        TlsKeySchedule.DeriveSecret(hash, handshakeSecret, "derived"u8, emptyHash, derived);
        TlsKeySchedule.Extract(hash, derived, zeros, masterSecret);

        // REALITY: the auth key the client derives, from the other half of its key_share exchange,
        // and a leaf certificate whose signature field is the HMAC the client checks.
        byte[] authKey = new byte[RealityAuth.AuthKeySize];
        RealityAuth.DeriveAuthKey(authKey, realityPrivateKey, clientKeyShare, clientHello.AsSpan(6, 32));
        byte[] leafPublicKey = RandomNumberGenerator.GetBytes(32);
        byte[] certificate = Ed25519Certificate(leafPublicKey, HMACSHA512.HashData(authKey, leafPublicKey));

        byte[] encryptedExtensions = HandshakeMessage(8, [0, 0]);
        byte[] certificateMessage = HandshakeMessage(
            11, [0, .. UInt24(certificate.Length + 5), .. UInt24(certificate.Length), .. certificate, 0, 0]);
        byte[] certificateVerify = HandshakeMessage(15, [0x08, 0x07, 0, 64, .. new byte[64]]);

        transcript.AppendData(encryptedExtensions);
        transcript.AppendData(certificateMessage);
        transcript.AppendData(certificateVerify);

        byte[] verifyData = new byte[suite.HashLength];
        TlsKeySchedule.FinishedVerifyData(hash, serverHandshakeTraffic, transcript.GetCurrentHash(), verifyData);
        byte[] finished = HandshakeMessage(20, verifyData);

        transcript.AppendData(finished);
        TlsKeySchedule.DeriveSecret(
            hash, masterSecret, "s ap traffic"u8, transcript.GetCurrentHash(), serverApplicationTraffic);

        using var handshakeKeys = new TlsRecordProtection(suite, serverHandshakeTraffic);
        using var applicationKeys = new TlsRecordProtection(suite, serverApplicationTraffic);

        byte[] beforeFinished = [.. encryptedExtensions, .. certificateMessage, .. certificateVerify];

        var wire = new List<byte>();
        wire.AddRange(Record(TlsContentTypeForTests.Handshake, serverHello));
        wire.AddRange(Record(TlsContentTypeForTests.ChangeCipherSpec, [1]));

        switch (flight)
        {
            case Flight.WellFormed:
                wire.AddRange(Sealed(handshakeKeys, TlsContentTypeForTests.Handshake, [.. beforeFinished, .. finished]));
                wire.AddRange(Sealed(applicationKeys, TlsContentTypeForTests.ApplicationData, ServerGreeting));
                break;

            case Flight.ApplicationDataBeforeFinished:
                wire.AddRange(Sealed(handshakeKeys, TlsContentTypeForTests.Handshake, beforeFinished));
                wire.AddRange(Sealed(handshakeKeys, TlsContentTypeForTests.ApplicationData, ServerGreeting));
                wire.AddRange(Sealed(handshakeKeys, TlsContentTypeForTests.Handshake, finished));
                break;

            case Flight.HandshakeBytesAfterFinished:
                // A NewSessionTicket belongs under the application keys. Sharing the Finished's
                // record puts it under the handshake keys instead, across the key change.
                byte[] ticket = HandshakeMessage(4, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);
                wire.AddRange(Sealed(
                    handshakeKeys, TlsContentTypeForTests.Handshake, [.. beforeFinished, .. finished, .. ticket]));
                break;
        }

        return wire.ToArray();
    }

    /// <summary>Finds the client's X25519 key_share in its raw ClientHello, as a server has to.</summary>
    private static byte[] ClientKeyShare(byte[] clientHello)
    {
        int offset = RealityAuth.SessionIdOffset + RealityAuth.SessionIdSize;
        offset += 2 + ((clientHello[offset] << 8) | clientHello[offset + 1]); // cipher suites
        offset += 1 + clientHello[offset];                                     // compression methods
        int end = offset + 2 + ((clientHello[offset] << 8) | clientHello[offset + 1]);
        offset += 2;

        while (offset < end)
        {
            int type = (clientHello[offset] << 8) | clientHello[offset + 1];
            int length = (clientHello[offset + 2] << 8) | clientHello[offset + 3];
            offset += 4;

            // key_share: the list length, then each entry's group and key length ahead of its key.
            if (type == 51 && clientHello[offset + 2] == 0x00 && clientHello[offset + 3] == 0x1D)
                return clientHello.AsSpan(offset + 6, X25519.KeySize).ToArray();

            offset += length;
        }

        throw new InvalidOperationException("The ClientHello offers no X25519 key_share.");
    }

    private static byte[] HandshakeMessage(byte type, ReadOnlySpan<byte> body)
    {
        byte[] message = new byte[4 + body.Length];
        message[0] = type;
        UInt24(body.Length).CopyTo(message, 1);
        body.CopyTo(message.AsSpan(4));
        return message;
    }

    private static byte[] UInt24(int value) => [(byte)(value >> 16), (byte)(value >> 8), (byte)value];

    /// <summary>Seals one record under <paramref name="keys"/>, with its real type inside.</summary>
    private static byte[] Sealed(TlsRecordProtection keys, TlsContentTypeForTests type, ReadOnlySpan<byte> content)
    {
        byte[] inner = [.. content, (byte)type];
        int length = inner.Length + TlsCipherSuite.TagLength;

        byte[] record = new byte[5 + length];
        record[0] = (byte)TlsContentTypeForTests.ApplicationData;
        record[1] = 3;
        record[2] = 3;
        record[3] = (byte)(length >> 8);
        record[4] = (byte)length;

        keys.Protect(
            inner,
            record.AsSpan(5, inner.Length),
            record.AsSpan(5 + inner.Length, TlsCipherSuite.TagLength),
            record.AsSpan(0, 5));

        return record;
    }

    /// <summary>
    /// A minimal DER certificate carrying an Ed25519 key and the given signature field, which is
    /// all the client reads out of a REALITY certificate.
    /// </summary>
    private static byte[] Ed25519Certificate(byte[] publicKey, byte[] signature)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);

        using (writer.PushSequence())
        {
            using (writer.PushSequence()) // tbsCertificate
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                    writer.WriteInteger(2); // version: v3

                writer.WriteInteger(1); // serialNumber
                WriteEd25519Algorithm(writer);
                writer.WriteEncodedValue([0x30, 0x00]); // issuer: an empty name

                using (writer.PushSequence()) // validity
                {
                    writer.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(-1));
                    writer.WriteUtcTime(DateTimeOffset.UtcNow.AddDays(1));
                }

                writer.WriteEncodedValue([0x30, 0x00]); // subject: an empty name

                using (writer.PushSequence()) // subjectPublicKeyInfo
                {
                    WriteEd25519Algorithm(writer);
                    writer.WriteBitString(publicKey);
                }
            }

            WriteEd25519Algorithm(writer);
            writer.WriteBitString(signature);
        }

        return writer.Encode();
    }

    private static void WriteEd25519Algorithm(AsnWriter writer)
    {
        using (writer.PushSequence())
            writer.WriteObjectIdentifier("1.3.101.112");
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
