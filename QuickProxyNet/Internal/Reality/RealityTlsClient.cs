using System.Buffers;
using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace QuickProxyNet;

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
    /// Cap on handshake messages in the server's flight. Four is the real number; the margin is
    /// for servers that are odd rather than hostile.
    /// </summary>
    private const int MaxFlightMessages = 8;

    /// <summary>The one-byte ChangeCipherSpec payload, which never varies.</summary>
    private static readonly byte[] ChangeCipherSpecPayload = [1];

    /// <summary>
    /// Every secret the handshake derives, in one pooled buffer.
    /// </summary>
    /// <remarks>
    /// Individually these are seven allocations of 32 to 48 bytes — nothing worth chasing once
    /// per connection. Together they are the reason a single <c>finally</c> can guarantee all of
    /// them are cleared. The seven separate <see cref="CryptographicOperations.ZeroMemory"/> calls
    /// this replaces were correct, and were exactly the shape a later edit forgets to extend:
    /// add an eighth secret and nothing tells you the clearing did not follow.
    /// </remarks>
    private readonly struct HandshakeSecrets(byte[] buffer, int hashLength)
    {
        public static HandshakeSecrets Rent(int hashLength) =>
            new(ArrayPool<byte>.Shared.Rent(X25519.KeySize + (6 * hashLength)), hashLength);

        /// <summary>The raw X25519 shared secret, before the key schedule touches it.</summary>
        public Span<byte> Shared => buffer.AsSpan(0, X25519.KeySize);

        public Span<byte> HandshakeSecret => At(0);
        public Span<byte> ClientHandshakeTraffic => At(1);
        public Span<byte> ServerHandshakeTraffic => At(2);
        public Span<byte> MasterSecret => At(3);
        public Span<byte> ClientApplicationTraffic => At(4);
        public Span<byte> ServerApplicationTraffic => At(5);

        private Span<byte> At(int index) =>
            buffer.AsSpan(X25519.KeySize + (index * hashLength), hashLength);

        /// <summary>Clears every secret and returns the buffer to the pool.</summary>
        public void Return() => ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
    }

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
        TlsClientHello.Result hello = default;
        HandshakeReader? messages = null;

        try
        {
            // ---- ClientHello, with the REALITY blob sealed into its session id ----
            hello = TlsClientHello.Build(options.ServerName, options.Alpn);

            RealityAuth.DeriveAuthKey(authKey, hello.PrivateKey, options.PublicKey, hello.Handshake.AsSpan(6, 32));

            Span<byte> shortId = stackalloc byte[RealityAuth.ShortIdSize];
            RealityAuth.ParseShortId(shortId, options.ShortId);

            RealityAuth.SealSessionId(
                hello.Handshake,
                authKey,
                shortId,
                (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                options.ClientVersion);

            await records.WriteAsync(TlsContentType.Handshake, hello.Handshake, cancellationToken).ConfigureAwait(false);

            // ---- ServerHello ----
            messages = new HandshakeReader(records);
            HandshakeMessage serverHello = await messages.NextAsync(cancellationToken).ConfigureAwait(false);
            if (serverHello.Type != TlsHandshakeType.ServerHello)
                throw new RealityHandshakeException($"Expected a ServerHello, got {serverHello.Type}.");

            ServerHello parsed = ParseServerHello(serverHello.Raw, hello.Handshake);

            // Everything after the ServerHello is encrypted, so a plaintext handshake byte still
            // buffered here was never authenticated — it came from somebody on the path, not from
            // the server. It would otherwise be handed out later as if it had been decrypted.
            if (messages.HasBufferedBytes)
                throw new RealityHandshakeException(
                    "The peer sent unencrypted handshake bytes after its ServerHello. They cannot be " +
                    "authenticated, so the connection is refused.");

            // The transcript hash cannot start until the suite names its hash, so the hello bytes
            // are replayed into it here rather than fed as they were sent.
            using IncrementalHash transcript = IncrementalHash.CreateHash(parsed.Suite.Hash);
            transcript.AppendData(hello.Handshake);
            transcript.AppendData(serverHello.Raw);

            // ---- Key schedule ----
            HandshakeSecrets secrets = HandshakeSecrets.Rent(parsed.Suite.HashLength);

            try
            {
                try
                {
                    X25519.Agree(secrets.Shared, hello.PrivateKey, parsed.KeyShare);
                }
                catch (CryptographicException ex)
                {
                    // A key_share that lands on a low-order point yields an all-zero shared
                    // secret; RFC 7748 §6.1 says abort. It is the peer's choice of key, not ours.
                    throw new RealityHandshakeException(
                        "The server's key_share is a low-order X25519 point; the handshake is refused.", ex);
                }

                DeriveHandshakeSecrets(
                    parsed.Suite, secrets.Shared, transcript.GetCurrentHash(),
                    secrets.HandshakeSecret, secrets.ClientHandshakeTraffic,
                    secrets.ServerHandshakeTraffic, secrets.MasterSecret);

                records.Read = new TlsRecordProtection(parsed.Suite, secrets.ServerHandshakeTraffic);

                // ---- Server flight ----
                byte[]? leafCertificate = null;
                bool serverFinished = false;
                int flightMessages = 0;

                while (!serverFinished)
                {
                    HandshakeMessage message = await messages.NextAsync(cancellationToken).ConfigureAwait(false);

                    // A real flight is EncryptedExtensions, Certificate, CertificateVerify,
                    // Finished — four messages. A peer that keeps sending valid-looking ones
                    // and never a Finished would otherwise hold this loop open for as long as
                    // it cares to; nothing it sends costs us memory, only time without end.
                    if (++flightMessages > MaxFlightMessages)
                        throw new RealityHandshakeException(
                            $"The server sent more than {MaxFlightMessages} handshake messages without a Finished.");

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
                            VerifyServerFinished(
                                parsed.Suite, secrets.ServerHandshakeTraffic,
                                transcript.GetCurrentHash(), message.Body.Span);
                            serverFinished = true;
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
                await records.WriteAsync(TlsContentType.ChangeCipherSpec, ChangeCipherSpecPayload, cancellationToken)
                    .ConfigureAwait(false);

                records.Write = new TlsRecordProtection(parsed.Suite, secrets.ClientHandshakeTraffic);

                byte[] finished = BuildFinished(
                    parsed.Suite, secrets.ClientHandshakeTraffic, transcriptAfterServerFinished);
                await records.WriteAsync(TlsContentType.Handshake, finished, cancellationToken).ConfigureAwait(false);

                // ---- Application keys ----
                TlsKeySchedule.DeriveSecret(
                    parsed.Suite.Hash, secrets.MasterSecret, "c ap traffic"u8,
                    transcriptAfterServerFinished, secrets.ClientApplicationTraffic);
                TlsKeySchedule.DeriveSecret(
                    parsed.Suite.Hash, secrets.MasterSecret, "s ap traffic"u8,
                    transcriptAfterServerFinished, secrets.ServerApplicationTraffic);

                records.Write?.Dispose();
                records.Read?.Dispose();
                records.Write = new TlsRecordProtection(parsed.Suite, secrets.ClientApplicationTraffic);
                records.Read = new TlsRecordProtection(parsed.Suite, secrets.ServerApplicationTraffic);

                return new RealityTlsStream(transport, records, messages.Leftover);
            }
            finally
            {
                secrets.Return();
            }
        }
        catch (EndOfStreamException ex)
        {
            records.Dispose();
            // The peer hung up before the handshake finished. A REALITY server with no fallback
            // does exactly this when it does not recognise the client, so the hint matters.
            throw new RealityHandshakeException(ProxyErrorCode.ConnectionFailed,
                "The server closed the connection in the middle of the TLS handshake. For a REALITY " +
                "server that usually means it did not accept the client: check pbk, sid and sni, and " +
                "that this machine's clock is roughly right.", ex);
        }
        catch
        {
            records.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(authKey);

            // The ephemeral scalar is the value the whole session can be recomputed from — every
            // other secret here is already cleared, and leaving this one on the heap would make
            // that discipline pointless.
            if (hello.PrivateKey is not null)
                CryptographicOperations.ZeroMemory(hello.PrivateKey);

            // Safe here: the stream returned above has already copied whatever Leftover held.
            messages?.Return();
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

    private static void VerifyServerFinished(
        TlsCipherSuite suite, ReadOnlySpan<byte> serverTraffic, ReadOnlySpan<byte> transcriptHash, ReadOnlySpan<byte> body)
    {
        Span<byte> expected = stackalloc byte[suite.HashLength];
        TlsKeySchedule.FinishedVerifyData(suite.Hash, serverTraffic, transcriptHash, expected);

        if (body.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(expected, body))
            throw new RealityHandshakeException(ProxyErrorCode.AuthFailed,
                "The server's Finished did not verify. The peer does not hold the private key for the " +
                "key_share it sent, so the connection is not with the server we negotiated with.");
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
            throw new RealityHandshakeException(ProxyErrorCode.AuthFailed,
                $"The peer presented an ordinary certificate for '{serverName}' rather than a REALITY one. " +
                "The handshake was relayed to the real site, which means the server did not recognise our " +
                "authentication — check the public key, the short id and the clock.");

        if (!RealityAuth.VerifyCertificate(authKey, publicKey, signature))
            throw new RealityHandshakeException(ProxyErrorCode.AuthFailed,
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

    /// <summary>
    /// Parses a ServerHello, checking every length before it is used.
    /// </summary>
    /// <param name="raw">The ServerHello handshake message.</param>
    /// <param name="clientHello">
    /// Our own hello, for the <c>legacy_session_id_echo</c> comparison RFC 8446 §4.1.3 requires.
    /// </param>
    /// <remarks>
    /// Every malformed input has to leave as a <see cref="RealityHandshakeException"/> naming what
    /// was wrong. A raw <see cref="IndexOutOfRangeException"/> escaping from here would still fail
    /// closed, but it would tell whoever is debugging nothing at all about the peer.
    /// </remarks>
    private static ServerHello ParseServerHello(byte[] raw, ReadOnlySpan<byte> clientHello)
    {
        ReadOnlySpan<byte> body = raw.AsSpan(4);

        ReadOnlySpan<byte> random = Take(ref body, 34, "the version and random")[2..];
        if (random.SequenceEqual(HelloRetryRequestRandom))
            throw new RealityHandshakeException(
                "The server sent a HelloRetryRequest, which this client does not implement. It means the " +
                "server rejected the offered X25519 group.");

        int sessionIdLength = Take(ref body, 1, "the session id length")[0];
        ReadOnlySpan<byte> sessionIdEcho = Take(ref body, sessionIdLength, "the session id");

        // RFC 8446 §4.1.3: the client MUST verify the echo. For REALITY it is more than a
        // formality — the session id is where our sealed authentication blob lives, so a
        // mismatch means the hello that reached the server was not the one we sent.
        ReadOnlySpan<byte> sessionIdSent =
            clientHello.Slice(RealityAuth.SessionIdOffset, RealityAuth.SessionIdSize);

        if (!sessionIdEcho.SequenceEqual(sessionIdSent))
            throw new RealityHandshakeException(
                "The server echoed a different session id than we sent. The ClientHello was altered in " +
                "flight, or the answer came from somewhere else.");

        ushort suiteId = BinaryPrimitives.ReadUInt16BigEndian(Take(ref body, 2, "the cipher suite"));

        if (Take(ref body, 1, "the compression method")[0] != 0)
            throw new RealityHandshakeException("The server selected a compression method; TLS 1.3 has none.");

        TlsCipherSuite suite = TlsCipherSuite.FromId(suiteId)
            ?? throw new RealityHandshakeException($"The server chose cipher suite 0x{suiteId:X4}, which we did not offer.");

        int extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(Take(ref body, 2, "the extensions length"));
        ReadOnlySpan<byte> extensions = Take(ref body, extensionsLength, "the extensions");

        byte[]? keyShare = null;
        bool sawTls13 = false;

        while (!extensions.IsEmpty)
        {
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(Take(ref extensions, 2, "an extension type"));
            int length = BinaryPrimitives.ReadUInt16BigEndian(Take(ref extensions, 2, "an extension length"));
            ReadOnlySpan<byte> data = Take(ref extensions, length, $"extension {type}");

            switch (type)
            {
                case 43 when data.Length == 2 && BinaryPrimitives.ReadUInt16BigEndian(data) == 0x0304:
                    sawTls13 = true;
                    break;

                case 51 when data.Length >= 4:
                    ushort group = BinaryPrimitives.ReadUInt16BigEndian(data);
                    int shareLength = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
                    if (group == 0x001D && shareLength == X25519.KeySize && data.Length >= 4 + shareLength)
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

    /// <summary>
    /// Consumes <paramref name="count"/> bytes from the front of <paramref name="source"/>,
    /// failing with a description rather than an index-out-of-range.
    /// </summary>
    /// <param name="source">The span to advance; on return it starts past the taken bytes.</param>
    /// <param name="count">How many bytes the field needs.</param>
    /// <param name="what">What the bytes are, for the failure message.</param>
    private static ReadOnlySpan<byte> Take(ref ReadOnlySpan<byte> source, int count, string what)
    {
        if (count < 0 || source.Length < count)
            throw new RealityHandshakeException(
                $"The peer's message ended before {what}: needed {count} more bytes, had {source.Length}.");

        ReadOnlySpan<byte> taken = source[..count];
        source = source[count..];
        return taken;
    }

    /// <summary>Reads TLS's three-byte big-endian length.</summary>
    private static int ReadUInt24(ReadOnlySpan<byte> source) =>
        (source[0] << 16) | (source[1] << 8) | source[2];

    /// <summary>Reads the first certificate out of a TLS 1.3 Certificate message body.</summary>
    private static byte[] ExtractLeafCertificate(ReadOnlyMemory<byte> body)
    {
        ReadOnlySpan<byte> span = body.Span;

        int contextLength = Take(ref span, 1, "the certificate request context length")[0];
        Take(ref span, contextLength, "the certificate request context");

        int listLength = ReadUInt24(Take(ref span, 3, "the certificate list length"));
        ReadOnlySpan<byte> list = Take(ref span, listLength, "the certificate list");

        if (list.IsEmpty)
            throw new RealityHandshakeException("The server sent an empty certificate list.");

        int certificateLength = ReadUInt24(Take(ref list, 3, "the leaf certificate length"));
        return Take(ref list, certificateLength, "the leaf certificate").ToArray();
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
        /// <summary>Largest handshake message we will reassemble, well past any real one.</summary>
        private const int MaxHandshakeMessage = 1 << 18;

        /// <summary>Cap on early application data, so a flood cannot exhaust memory.</summary>
        private const int MaxLeftover = 1 << 16;

        /// <summary>
        /// Cap on ChangeCipherSpec records, which carry no meaning and are dropped.
        /// </summary>
        /// <remarks>
        /// RFC 8446 §5 calls for a limit: without one, a peer can hold the handshake open forever
        /// by sending nothing else, and the loop below would spin on it.
        /// </remarks>
        private const int MaxChangeCipherSpec = 8;

        /// <summary>
        /// Cap on empty application-data records during the handshake. Each is legal on its own
        /// and carries nothing; a stream of them is a peer keeping us busy.
        /// </summary>
        private const int MaxEmptyRecords = 64;

        private byte[] _buffer = ArrayPool<byte>.Shared.Rent(TlsRecordStream.MaxCiphertext);
        private int _length;
        private int _consumed;
        private int _changeCipherSpecSeen;
        private int _emptyRecordsSeen;

        /// <summary>Application data that arrived before the handshake finished.</summary>
        public List<byte> Leftover { get; } = [];

        /// <summary>Whether any handshake bytes are still buffered but unconsumed.</summary>
        public bool HasBufferedBytes => _length - _consumed > 0;

        /// <summary>
        /// Returns the reassembly buffer to the pool. <see cref="Leftover"/> is a separate list
        /// and stays valid afterwards.
        /// </summary>
        public void Return()
        {
            if (_buffer.Length == 0)
                return;

            // Cleared: it held the server's certificate and every other handshake message.
            ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
            _buffer = [];
            _length = 0;
            _consumed = 0;
        }

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
                        if (++_changeCipherSpecSeen > MaxChangeCipherSpec)
                            throw new RealityHandshakeException(
                                "The peer sent nothing but ChangeCipherSpec records.");

                        continue;

                    case TlsContentType.Alert:
                        throw new RealityHandshakeException(DescribeAlert(record.Payload.Span));

                    case TlsContentType.ApplicationData when records.Read is null:
                        // Before the server's keys exist, TlsRecordStream hands records back
                        // verbatim — unauthenticated. Buffering one here would put bytes an
                        // on-path attacker chose at the head of the "authenticated" tunnel, and
                        // the handshake would still complete: injected records never enter the
                        // transcript, so Finished and the REALITY HMAC both still verify.
                        throw new RealityHandshakeException(
                            "The peer sent application data before its keys were established. " +
                            "Nothing can authenticate those bytes, so they are refused rather " +
                            "than passed to the caller.");

                    case TlsContentType.ApplicationData:
                        if (record.Payload.IsEmpty && ++_emptyRecordsSeen > MaxEmptyRecords)
                            throw new RealityHandshakeException(
                                $"The peer sent more than {MaxEmptyRecords} empty application-data records " +
                                "during the handshake.");

                        if (Leftover.Count + record.Payload.Length > MaxLeftover)
                            throw new RealityHandshakeException(
                                $"The peer sent more than {MaxLeftover} bytes of application data before " +
                                "finishing its handshake.");

                        Leftover.AddRange(record.Payload.ToArray());
                        continue;

                    case TlsContentType.Handshake:
                        // RFC 8446 §5.1: zero-length handshake records are forbidden. Accepting
                        // one is harmless; accepting them without end is a peer's free spin.
                        if (record.Payload.IsEmpty)
                            throw new RealityHandshakeException(
                                "The peer sent a zero-length handshake record, which TLS 1.3 forbids.");

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

            if (_length + data.Length > MaxHandshakeMessage)
                throw new RealityHandshakeException(
                    $"The peer's handshake message exceeded {MaxHandshakeMessage} bytes.");

            if (_length + data.Length > _buffer.Length)
            {
                // Grown by renting, not by Array.Resize: a resized array does not come from the
                // pool, and returning it later would put a foreign buffer into the shared pool.
                byte[] bigger = ArrayPool<byte>.Shared.Rent(Math.Max(_buffer.Length * 2, _length + data.Length));
                _buffer.AsSpan(0, _length).CopyTo(bigger);
                ArrayPool<byte>.Shared.Return(_buffer, clearArray: true);
                _buffer = bigger;
            }

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
/// <remarks>
/// A <see cref="ProxyProtocolException"/>, so a caller that already catches those and branches
/// on <see cref="ProxyProtocolException.ErrorCode"/> sees REALITY failures too. Two codes are
/// used: <see cref="ProxyErrorCode.AuthFailed"/> when the peer did not prove it is the server
/// we configured — it relayed us to the decoy site, or its certificate is not bound to our
/// shared secret — and <see cref="ProxyErrorCode.InvalidResponse"/> for everything else, which
/// is the peer breaking TLS or sending something this client does not implement. The first is
/// "check pbk, sid and sni"; the second is not something the caller can fix by reconfiguring.
/// </remarks>
public sealed class RealityHandshakeException : ProxyProtocolException
{
    /// <summary>Creates the exception with <see cref="ProxyErrorCode.InvalidResponse"/>.</summary>
    /// <param name="message">What went wrong.</param>
    public RealityHandshakeException(string message) : base(ProxyErrorCode.InvalidResponse, message)
    {
    }

    /// <summary>Creates the exception with an explicit code.</summary>
    /// <param name="errorCode">Why, in terms a caller can branch on.</param>
    /// <param name="message">What went wrong.</param>
    public RealityHandshakeException(ProxyErrorCode errorCode, string message) : base(errorCode, message)
    {
    }

    /// <summary>Creates the exception with <see cref="ProxyErrorCode.InvalidResponse"/>.</summary>
    /// <param name="message">What went wrong.</param>
    /// <param name="innerException">The underlying failure.</param>
    public RealityHandshakeException(string message, Exception innerException)
        : base(ProxyErrorCode.InvalidResponse, message, innerException)
    {
    }

    /// <summary>Creates the exception with an explicit code and an underlying failure.</summary>
    /// <param name="errorCode">Why, in terms a caller can branch on.</param>
    /// <param name="message">What went wrong.</param>
    /// <param name="innerException">The underlying failure.</param>
    public RealityHandshakeException(ProxyErrorCode errorCode, string message, Exception innerException)
        : base(errorCode, message, innerException)
    {
    }
}
