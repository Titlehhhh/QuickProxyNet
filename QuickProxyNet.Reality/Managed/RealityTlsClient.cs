using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace QuickProxyNet.Reality.Managed;

/// <summary>Settings for a managed REALITY handshake.</summary>
internal sealed class RealityTlsOptions
{
    /// <summary>SNI to present — the borrowed site's name (<c>sni</c> in the share link).</summary>
    public required string ServerName { get; init; }

    /// <summary>The server's REALITY public key, 32 bytes (<c>pbk</c>, base64url in the link).</summary>
    public required byte[] PublicKey { get; init; }

    /// <summary>The short id as hex (<c>sid</c>), or null.</summary>
    public string? ShortId { get; init; }

    /// <summary>ALPN identifiers to offer, or null.</summary>
    public IReadOnlyList<string>? Alpn { get; init; }

    /// <summary>
    /// The three version bytes placed in the sealed session id. Servers may set a minimum.
    /// </summary>
    public byte[] ClientVersion { get; init; } = [26, 3, 27];
}

/// <summary>
/// A TLS 1.3 client that speaks REALITY, implemented in managed code.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not a general TLS implementation. It supports exactly one handshake shape: full
/// 1-RTT, no PSK, no resumption, no client certificates, no HelloRetryRequest, no renegotiation.
/// Everything outside that shape is rejected with a message naming what happened rather than
/// worked around, because every "handle this case too" is another chance to end up in a state the
/// tests do not cover.
/// </para>
/// <para>
/// <b>What is verified, and what is not.</b> The server's Finished is checked — that is the proof
/// the peer holds the private key for the <c>key_share</c> it sent, and it is not optional. The
/// certificate's Ed25519 CertificateVerify signature is <b>not</b> checked, because REALITY's own
/// test subsumes it: the leaf certificate is generated per connection and bound to the shared
/// secret by <c>HMAC-SHA512(authKey, publicKey) == certificate.signature</c>, which nobody
/// without the REALITY private key can produce. Outside REALITY that omission would be a hole;
/// here the HMAC is the stronger of the two checks. See
/// <see cref="RealityAuth.VerifyCertificate"/>.
/// </para>
/// <para>
/// The ClientHello it sends is not a browser fingerprint yet — see <see cref="TlsClientHello"/>
/// for why that matters more than it might appear.
/// </para>
/// </remarks>
internal sealed class RealityTlsClient
{
    /// <summary>The fixed ServerHello.random that marks a HelloRetryRequest (RFC 8446 §4.1.3).</summary>
    private static ReadOnlySpan<byte> HelloRetryRequestRandom =>
    [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    ];

    private const string Ed25519Oid = "1.3.101.112";

    /// <summary>
    /// Performs the handshake over <paramref name="transport"/> and returns the tunnelled stream.
    /// </summary>
    /// <param name="transport">A connected stream to the REALITY server.</param>
    /// <param name="options">The share link's REALITY parameters.</param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <exception cref="RealityHandshakeException">
    /// The peer is not the REALITY server we authenticated to, or the handshake used something
    /// this client does not implement.
    /// </exception>
    public static async ValueTask<Stream> HandshakeAsync(
        Stream transport, RealityTlsOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(options);

        if (options.PublicKey.Length != X25519.KeySize)
            throw new ArgumentException($"A REALITY public key is {X25519.KeySize} bytes.", nameof(options));

        var records = new TlsRecordStream(transport);
        byte[] authKey = new byte[RealityAuth.AuthKeySize];

        try
        {
            // ---- ClientHello, with the REALITY blob sealed into its session id ----
            TlsClientHello.Result hello = TlsClientHello.Build(options.ServerName, options.Alpn);

            RealityAuth.DeriveAuthKey(authKey, hello.PrivateKey, options.PublicKey, hello.Handshake.AsSpan(6, 32));

            byte[] shortId = new byte[RealityAuth.ShortIdSize];
            RealityAuth.ParseShortId(shortId, options.ShortId);

            RealityAuth.SealSessionId(
                hello.Handshake,
                authKey,
                shortId,
                (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                options.ClientVersion);

            await records.WriteAsync(TlsContentType.Handshake, hello.Handshake, cancellationToken).ConfigureAwait(false);

            // ---- ServerHello ----
            var messages = new HandshakeReader(records);
            HandshakeMessage serverHello = await messages.NextAsync(cancellationToken).ConfigureAwait(false);
            if (serverHello.Type != TlsHandshakeType.ServerHello)
                throw new RealityHandshakeException($"Expected a ServerHello, got {serverHello.Type}.");

            ServerHello parsed = ParseServerHello(serverHello.Raw);

            // The transcript hash cannot start until the suite names its hash, so the hello bytes
            // are replayed into it here rather than fed as they were sent.
            using IncrementalHash transcript = IncrementalHash.CreateHash(parsed.Suite.Hash);
            transcript.AppendData(hello.Handshake);
            transcript.AppendData(serverHello.Raw);

            // ---- Key schedule ----
            byte[] shared = new byte[X25519.KeySize];
            byte[] handshakeSecret = new byte[parsed.Suite.HashLength];
            byte[] clientHandshakeTraffic = new byte[parsed.Suite.HashLength];
            byte[] serverHandshakeTraffic = new byte[parsed.Suite.HashLength];
            byte[] masterSecret = new byte[parsed.Suite.HashLength];

            try
            {
                X25519.Agree(shared, hello.PrivateKey, parsed.KeyShare);

                DeriveHandshakeSecrets(
                    parsed.Suite, shared, transcript.GetCurrentHash(),
                    handshakeSecret, clientHandshakeTraffic, serverHandshakeTraffic, masterSecret);

                records.Read = new TlsRecordProtection(parsed.Suite, serverHandshakeTraffic);

                // ---- Server flight ----
                byte[]? leafCertificate = null;
                byte[]? serverVerifyData = null;

                while (serverVerifyData is null)
                {
                    HandshakeMessage message = await messages.NextAsync(cancellationToken).ConfigureAwait(false);

                    switch (message.Type)
                    {
                        case TlsHandshakeType.EncryptedExtensions:
                        case TlsHandshakeType.CertificateVerify:
                            transcript.AppendData(message.Raw);
                            break;

                        case TlsHandshakeType.Certificate:
                            leafCertificate = ExtractLeafCertificate(message.Body);
                            transcript.AppendData(message.Raw);
                            break;

                        case TlsHandshakeType.Finished:
                            // Verified against the transcript as it stood *before* this message.
                            serverVerifyData = VerifyServerFinished(
                                parsed.Suite, serverHandshakeTraffic, transcript.GetCurrentHash(), message.Body.Span);
                            transcript.AppendData(message.Raw);
                            break;

                        case TlsHandshakeType.CertificateRequest:
                            throw new RealityHandshakeException(
                                "The server asked for a client certificate, which this client does not implement. " +
                                "A REALITY server does not do this.");

                        default:
                            throw new RealityHandshakeException(
                                $"Unexpected {message.Type} in the server's handshake flight.");
                    }
                }

                if (leafCertificate is null)
                    throw new RealityHandshakeException("The server sent no certificate.");

                // ---- The REALITY decision ----
                AssertRealityServer(leafCertificate, authKey, options.ServerName);

                byte[] transcriptAfterServerFinished = transcript.GetCurrentHash();

                // ---- Client Finished ----
                // The ChangeCipherSpec is meaningless in TLS 1.3 and is sent only so middleboxes
                // on the path see the shape of a TLS 1.2 handshake, which is the whole point of a
                // protocol designed to look unremarkable.
                await records.WriteAsync(TlsContentType.ChangeCipherSpec, new byte[] { 1 }, cancellationToken)
                    .ConfigureAwait(false);

                records.Write = new TlsRecordProtection(parsed.Suite, clientHandshakeTraffic);

                byte[] finished = BuildFinished(parsed.Suite, clientHandshakeTraffic, transcriptAfterServerFinished);
                await records.WriteAsync(TlsContentType.Handshake, finished, cancellationToken).ConfigureAwait(false);

                // ---- Application keys ----
                byte[] clientApplication = new byte[parsed.Suite.HashLength];
                byte[] serverApplication = new byte[parsed.Suite.HashLength];
                try
                {
                    TlsKeySchedule.DeriveSecret(
                        parsed.Suite.Hash, masterSecret, "c ap traffic"u8, transcriptAfterServerFinished, clientApplication);
                    TlsKeySchedule.DeriveSecret(
                        parsed.Suite.Hash, masterSecret, "s ap traffic"u8, transcriptAfterServerFinished, serverApplication);

                    records.Write?.Dispose();
                    records.Read?.Dispose();
                    records.Write = new TlsRecordProtection(parsed.Suite, clientApplication);
                    records.Read = new TlsRecordProtection(parsed.Suite, serverApplication);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(clientApplication);
                    CryptographicOperations.ZeroMemory(serverApplication);
                }

                return new RealityTlsStream(transport, records, messages.Leftover);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(shared);
                CryptographicOperations.ZeroMemory(handshakeSecret);
                CryptographicOperations.ZeroMemory(clientHandshakeTraffic);
                CryptographicOperations.ZeroMemory(serverHandshakeTraffic);
                CryptographicOperations.ZeroMemory(masterSecret);
            }
        }
        catch
        {
            records.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authKey);
        }
    }

    private static void DeriveHandshakeSecrets(
        TlsCipherSuite suite,
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> transcriptHash,
        Span<byte> handshakeSecret,
        Span<byte> clientTraffic,
        Span<byte> serverTraffic,
        Span<byte> masterSecret)
    {
        Span<byte> zeros = stackalloc byte[suite.HashLength];
        Span<byte> early = stackalloc byte[suite.HashLength];
        Span<byte> derived = stackalloc byte[suite.HashLength];
        Span<byte> emptyHash = stackalloc byte[suite.HashLength];

        zeros.Clear();
        HashEmpty(suite, emptyHash);

        TlsKeySchedule.Extract(suite.Hash, zeros, zeros, early);
        TlsKeySchedule.DeriveSecret(suite.Hash, early, "derived"u8, emptyHash, derived);
        TlsKeySchedule.Extract(suite.Hash, derived, sharedSecret, handshakeSecret);

        TlsKeySchedule.DeriveSecret(suite.Hash, handshakeSecret, "c hs traffic"u8, transcriptHash, clientTraffic);
        TlsKeySchedule.DeriveSecret(suite.Hash, handshakeSecret, "s hs traffic"u8, transcriptHash, serverTraffic);

        TlsKeySchedule.DeriveSecret(suite.Hash, handshakeSecret, "derived"u8, emptyHash, derived);
        TlsKeySchedule.Extract(suite.Hash, derived, zeros, masterSecret);

        CryptographicOperations.ZeroMemory(early);
        CryptographicOperations.ZeroMemory(derived);
    }

    private static void HashEmpty(TlsCipherSuite suite, Span<byte> output)
    {
        if (suite.Hash == HashAlgorithmName.SHA384)
            SHA384.HashData(ReadOnlySpan<byte>.Empty, output);
        else
            SHA256.HashData(ReadOnlySpan<byte>.Empty, output);
    }

    private static byte[] VerifyServerFinished(
        TlsCipherSuite suite, ReadOnlySpan<byte> serverTraffic, ReadOnlySpan<byte> transcriptHash, ReadOnlySpan<byte> body)
    {
        Span<byte> expected = stackalloc byte[suite.HashLength];
        TlsKeySchedule.FinishedVerifyData(suite.Hash, serverTraffic, transcriptHash, expected);

        if (body.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(expected, body))
            throw new RealityHandshakeException(
                "The server's Finished did not verify. The peer does not hold the private key for the " +
                "key_share it sent, so the connection is not with the server we negotiated with.");

        return body.ToArray();
    }

    private static byte[] BuildFinished(
        TlsCipherSuite suite, ReadOnlySpan<byte> clientTraffic, ReadOnlySpan<byte> transcriptHash)
    {
        byte[] message = new byte[4 + suite.HashLength];
        message[0] = (byte)TlsHandshakeType.Finished;
        message[1] = 0;
        message[2] = (byte)(suite.HashLength >> 8);
        message[3] = (byte)suite.HashLength;

        TlsKeySchedule.FinishedVerifyData(suite.Hash, clientTraffic, transcriptHash, message.AsSpan(4));
        return message;
    }

    /// <summary>
    /// Throws unless the leaf certificate proves the peer knows the REALITY shared secret.
    /// </summary>
    private static void AssertRealityServer(byte[] certificate, ReadOnlySpan<byte> authKey, string serverName)
    {
        if (!TryReadEd25519Certificate(certificate, out byte[]? publicKey, out byte[]? signature))
            throw new RealityHandshakeException(
                $"The peer presented an ordinary certificate for '{serverName}' rather than a REALITY one. " +
                "The handshake was relayed to the real site, which means the server did not recognise our " +
                "authentication — check the public key, the short id and the clock.");

        if (!RealityAuth.VerifyCertificate(authKey, publicKey, signature))
            throw new RealityHandshakeException(
                "The peer's certificate is not bound to our REALITY shared secret. Refusing to tunnel: " +
                "sending the proxy credentials now would hand them to whoever answered.");
    }

    /// <summary>
    /// Pulls the Ed25519 public key and the signature out of a DER certificate.
    /// </summary>
    /// <remarks>
    /// Hand-parsed because <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2"/>
    /// exposes no signature bytes, and REALITY's whole check is against that field.
    /// </remarks>
    private static bool TryReadEd25519Certificate(byte[] der, out byte[] publicKey, out byte[] signature)
    {
        publicKey = [];
        signature = [];

        try
        {
            AsnReader outer = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();

            AsnReader tbs = outer.ReadSequence();
            if (tbs.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                tbs.ReadEncodedValue(); // version

            tbs.ReadEncodedValue(); // serialNumber
            tbs.ReadEncodedValue(); // signature algorithm
            tbs.ReadEncodedValue(); // issuer
            tbs.ReadEncodedValue(); // validity
            tbs.ReadEncodedValue(); // subject

            AsnReader subjectPublicKeyInfo = tbs.ReadSequence();
            AsnReader algorithm = subjectPublicKeyInfo.ReadSequence();
            if (algorithm.ReadObjectIdentifier() != Ed25519Oid)
                return false;

            publicKey = subjectPublicKeyInfo.ReadBitString(out _);

            outer.ReadEncodedValue(); // signatureAlgorithm
            signature = outer.ReadBitString(out _);

            return publicKey.Length == 32;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private readonly record struct ServerHello(TlsCipherSuite Suite, byte[] KeyShare);

    private static ServerHello ParseServerHello(byte[] raw)
    {
        ReadOnlySpan<byte> body = raw.AsSpan(4);

        if (body.Length < 34)
            throw new RealityHandshakeException("The ServerHello is truncated.");

        ReadOnlySpan<byte> random = body.Slice(2, 32);
        if (random.SequenceEqual(HelloRetryRequestRandom))
            throw new RealityHandshakeException(
                "The server sent a HelloRetryRequest, which this client does not implement. It means the " +
                "server rejected the offered X25519 group.");

        int offset = 34;
        int sessionIdLength = body[offset++];
        offset += sessionIdLength;

        ushort suiteId = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        offset += 2;
        offset += 1; // legacy_compression_method

        TlsCipherSuite suite = TlsCipherSuite.FromId(suiteId)
            ?? throw new RealityHandshakeException($"The server chose cipher suite 0x{suiteId:X4}, which we did not offer.");

        int extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        offset += 2;
        ReadOnlySpan<byte> extensions = body.Slice(offset, extensionsLength);

        byte[]? keyShare = null;
        bool sawTls13 = false;

        while (extensions.Length >= 4)
        {
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(extensions);
            int length = BinaryPrimitives.ReadUInt16BigEndian(extensions[2..]);
            ReadOnlySpan<byte> data = extensions.Slice(4, length);
            extensions = extensions[(4 + length)..];

            switch (type)
            {
                case 43 when data.Length == 2 && BinaryPrimitives.ReadUInt16BigEndian(data) == 0x0304:
                    sawTls13 = true;
                    break;

                case 51 when data.Length >= 4:
                    ushort group = BinaryPrimitives.ReadUInt16BigEndian(data);
                    int shareLength = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
                    if (group == 0x001D && shareLength == X25519.KeySize)
                        keyShare = data.Slice(4, shareLength).ToArray();
                    break;
            }
        }

        if (!sawTls13)
            throw new RealityHandshakeException(
                "The server did not select TLS 1.3. REALITY exists only in TLS 1.3, so there is nothing to fall back to.");

        if (keyShare is null)
            throw new RealityHandshakeException("The server's key_share is missing or is not X25519.");

        return new ServerHello(suite, keyShare);
    }

    /// <summary>Reads the first certificate out of a TLS 1.3 Certificate message body.</summary>
    private static byte[] ExtractLeafCertificate(ReadOnlyMemory<byte> body)
    {
        ReadOnlySpan<byte> span = body.Span;

        if (span.Length < 4)
            throw new RealityHandshakeException("The Certificate message is truncated.");

        int contextLength = span[0];
        span = span[(1 + contextLength)..];

        int listLength = (span[0] << 16) | (span[1] << 8) | span[2];
        span = span.Slice(3, listLength);

        if (span.Length < 3)
            throw new RealityHandshakeException("The server sent an empty certificate list.");

        int certificateLength = (span[0] << 16) | (span[1] << 8) | span[2];
        return span.Slice(3, certificateLength).ToArray();
    }

    /// <summary>One complete handshake message.</summary>
    /// <param name="Type">The message type.</param>
    /// <param name="Raw">The whole message including its four-byte header — what the transcript hashes.</param>
    /// <param name="Body">The message body.</param>
    private readonly record struct HandshakeMessage(TlsHandshakeType Type, byte[] Raw, ReadOnlyMemory<byte> Body);

    /// <summary>
    /// Reassembles handshake messages out of records.
    /// </summary>
    /// <remarks>
    /// A handshake message may span records and several may share one, so the record boundary
    /// carries no meaning here. Anything that is not a handshake record is either dropped
    /// (ChangeCipherSpec) or fatal (Alert); application data arriving mid-handshake is kept for
    /// the stream, since the server may coalesce it with its last flight.
    /// </remarks>
    private sealed class HandshakeReader(TlsRecordStream records)
    {
        private byte[] _buffer = new byte[TlsRecordStream.MaxCiphertext];
        private int _length;
        private int _consumed;

        /// <summary>Application data that arrived before the handshake finished.</summary>
        public List<byte> Leftover { get; } = [];

        public async ValueTask<HandshakeMessage> NextAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                if (TryTake(out HandshakeMessage message))
                    return message;

                TlsRecordStream.Record record = await records.ReadAsync(cancellationToken).ConfigureAwait(false);

                switch (record.Type)
                {
                    case TlsContentType.ChangeCipherSpec:
                        continue;

                    case TlsContentType.Alert:
                        throw new RealityHandshakeException(DescribeAlert(record.Payload.Span));

                    case TlsContentType.ApplicationData:
                        Leftover.AddRange(record.Payload.ToArray());
                        continue;

                    case TlsContentType.Handshake:
                        Append(record.Payload.Span);
                        continue;

                    default:
                        throw new RealityHandshakeException($"Unexpected record type {record.Type} during the handshake.");
                }
            }
        }

        private void Append(ReadOnlySpan<byte> data)
        {
            Compact();

            if (_length + data.Length > _buffer.Length)
                Array.Resize(ref _buffer, Math.Max(_buffer.Length * 2, _length + data.Length));

            data.CopyTo(_buffer.AsSpan(_length));
            _length += data.Length;
        }

        private void Compact()
        {
            if (_consumed == 0)
                return;

            _buffer.AsSpan(_consumed, _length - _consumed).CopyTo(_buffer);
            _length -= _consumed;
            _consumed = 0;
        }

        private bool TryTake(out HandshakeMessage message)
        {
            message = default;

            int available = _length - _consumed;
            if (available < 4)
                return false;

            ReadOnlySpan<byte> span = _buffer.AsSpan(_consumed, available);
            int bodyLength = (span[1] << 16) | (span[2] << 8) | span[3];
            if (available < 4 + bodyLength)
                return false;

            byte[] raw = span[..(4 + bodyLength)].ToArray();
            _consumed += 4 + bodyLength;

            message = new HandshakeMessage((TlsHandshakeType)raw[0], raw, raw.AsMemory(4));
            return true;
        }

        private static string DescribeAlert(ReadOnlySpan<byte> payload)
        {
            if (payload.Length < 2)
                return "The server sent a malformed alert.";

            string level = payload[0] == 2 ? "fatal" : "warning";
            return $"The server sent a {level} TLS alert, description {payload[1]}.";
        }
    }
}

/// <summary>Raised when a managed REALITY handshake cannot be completed.</summary>
public sealed class RealityHandshakeException : Exception
{
    /// <summary>Creates the exception.</summary>
    /// <param name="message">What went wrong.</param>
    public RealityHandshakeException(string message) : base(message)
    {
    }

    /// <summary>Creates the exception.</summary>
    /// <param name="message">What went wrong.</param>
    /// <param name="innerException">The underlying failure.</param>
    public RealityHandshakeException(string message, Exception innerException) : base(message, innerException)
    {
    }
}
