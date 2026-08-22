using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace QuickProxyNet;

/// <summary>
/// Builds the TLS 1.3 ClientHello that carries REALITY's authentication.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is not yet a browser fingerprint, and must not be shipped as one.</b> The hello below
/// is a correct, minimal TLS 1.3 hello: enough for a server to accept, and enough to prove the
/// REALITY authentication is right. It is not byte-identical to any real browser — no GREASE, no
/// padding, a short extension list in the wrong order, and a bare X25519 <c>key_share</c> where
/// current Chrome sends <c>X25519MLKEM768</c>.
/// </para>
/// <para>
/// That distinction is the whole point of REALITY, so it is worth stating plainly: a client whose
/// hello merely <i>works</i> is more identifiable than one that fails, because it presents a
/// handshake that matches no deployed browser while claiming a browser's certificate. Shipping
/// this as a censorship-resistant client would put users in a smaller, stranger bucket than not
/// shipping it at all. Fingerprint fidelity is a separate piece of work, and until it lands this
/// type is a protocol test harness.
/// </para>
/// </remarks>
internal static class TlsClientHello
{
    private const ushort LegacyVersion = 0x0303;             // TLS 1.2, as TLS 1.3 requires
    private const ushort ExtensionServerName = 0;
    private const ushort ExtensionSupportedGroups = 10;
    private const ushort ExtensionSignatureAlgorithms = 13;
    private const ushort ExtensionAlpn = 16;
    private const ushort ExtensionSupportedVersions = 43;
    private const ushort ExtensionPskKeyExchangeModes = 45;
    private const ushort ExtensionKeyShare = 51;

    private const ushort GroupX25519 = 0x001D;
    private const ushort Tls13 = 0x0304;

    /// <summary>The result of building a hello: the message and the key material behind it.</summary>
    /// <param name="Handshake">
    /// The complete handshake message, starting at the handshake type byte. This is exactly the
    /// buffer REALITY seals over — <c>hello.Raw</c> on the Go side.
    /// </param>
    /// <param name="PrivateKey">The X25519 private key offered in <c>key_share</c>.</param>
    /// <param name="PublicKey">The matching public key.</param>
    internal readonly record struct Result(byte[] Handshake, byte[] PrivateKey, byte[] PublicKey);

    /// <summary>
    /// Builds a ClientHello offering a fresh X25519 <c>key_share</c>.
    /// </summary>
    /// <param name="serverName">SNI to present — for REALITY, the borrowed site's name.</param>
    /// <param name="alpn">ALPN identifiers, or null to omit the extension.</param>
    public static Result Build(string serverName, IReadOnlyList<string>? alpn = null)
    {
        byte[] privateKey = new byte[X25519.KeySize];
        byte[] publicKey = new byte[X25519.KeySize];
        X25519.GenerateKeyPair(privateKey, publicKey);

        // A hello lands around 300-600 bytes; sizing for it avoids the one resize the default
        // 512-byte buffer would always need.
        var writer = new TlsWriter(1024);

        writer.WriteByte(1); // handshake type: client_hello
        int body = writer.BeginVector24();

        writer.WriteUInt16(LegacyVersion);

        Span<byte> random = stackalloc byte[32];
        RandomNumberGenerator.Fill(random);
        writer.Write(random);

        // A full-length session id. TLS 1.3 clients send one for middlebox compatibility anyway,
        // and REALITY requires exactly 32 bytes because that is where the sealed blob goes.
        writer.WriteByte(RealityAuth.SessionIdSize);
        writer.WriteZeros(RealityAuth.SessionIdSize);

        int cipherSuites = writer.BeginVector16();
        writer.WriteUInt16(0x1301); // TLS_AES_128_GCM_SHA256
        writer.WriteUInt16(0x1302); // TLS_AES_256_GCM_SHA384

        // Offered only where the platform can actually do it. Advertising a suite the record
        // layer cannot build means a server may select it and the connection then fails with
        // "the server chose a suite we did not offer", which is both wrong and unhelpful.
        if (ChaCha20Poly1305.IsSupported)
            writer.WriteUInt16(0x1303); // TLS_CHACHA20_POLY1305_SHA256

        writer.EndVector(cipherSuites, 2);

        int compression = writer.BeginVector8();
        writer.WriteByte(0); // null
        writer.EndVector(compression, 1);

        int extensions = writer.BeginVector16();

        WriteServerName(writer, serverName);
        WriteSupportedGroups(writer);
        WriteSignatureAlgorithms(writer);
        WriteSupportedVersions(writer);
        WritePskKeyExchangeModes(writer);
        WriteKeyShare(writer, publicKey);

        if (alpn is { Count: > 0 })
            WriteAlpn(writer, alpn);

        writer.EndVector(extensions, 2);
        writer.EndVector(body, 3);

        return new Result(writer.ToArray(), privateKey, publicKey);
    }

    private static void WriteServerName(TlsWriter writer, string serverName)
    {
        writer.WriteUInt16(ExtensionServerName);
        int extension = writer.BeginVector16();

        int list = writer.BeginVector16();
        writer.WriteByte(0); // host_name
        int name = writer.BeginVector16();
        writer.Write(Encoding.ASCII.GetBytes(ToALabel(serverName)));
        writer.EndVector(name, 2);
        writer.EndVector(list, 2);

        writer.EndVector(extension, 2);
    }

    /// <summary>
    /// Converts a host name to the ASCII form SNI requires (RFC 6066: A-labels only).
    /// </summary>
    /// <remarks>
    /// <see cref="Encoding.ASCII"/> maps anything outside ASCII to <c>?</c>, so encoding an
    /// internationalised name directly would put a host nobody owns into the ClientHello and
    /// send it without a word. Punycode is the specified answer, and a name that cannot be
    /// converted is an error rather than something to approximate.
    /// </remarks>
    private static string ToALabel(string serverName)
    {
        foreach (char c in serverName)
        {
            if (c > 127)
            {
                try
                {
                    return new IdnMapping().GetAscii(serverName);
                }
                catch (ArgumentException ex)
                {
                    throw new ArgumentException(
                        $"'{serverName}' is not a host name that can be encoded for SNI.", nameof(serverName), ex);
                }
            }
        }

        return serverName;
    }

    private static void WriteSupportedGroups(TlsWriter writer)
    {
        writer.WriteUInt16(ExtensionSupportedGroups);
        int extension = writer.BeginVector16();

        int groups = writer.BeginVector16();
        writer.WriteUInt16(GroupX25519);
        writer.EndVector(groups, 2);

        writer.EndVector(extension, 2);
    }

    private static void WriteSignatureAlgorithms(TlsWriter writer)
    {
        writer.WriteUInt16(ExtensionSignatureAlgorithms);
        int extension = writer.BeginVector16();

        int algorithms = writer.BeginVector16();
        // Chrome's list, in Chrome's order. Both matter: JA4 appends the signature algorithms
        // unsorted, so a reordering changes the hash even though TLS does not care.
        //
        // ed25519 (0x0807) is deliberately absent, and it took an experiment to be sure. An
        // earlier comment here claimed it was load-bearing, on the reasoning that a REALITY
        // server answers with an Ed25519 certificate. It is not: the server generates that
        // certificate only after it has authenticated the client, and never consults
        // signature_algorithms for it. Removing it leaves the real-server handshake and tunnel
        // tests green, and Chrome does not send it.
        writer.WriteUInt16(0x0403); // ecdsa_secp256r1_sha256
        writer.WriteUInt16(0x0804); // rsa_pss_rsae_sha256
        writer.WriteUInt16(0x0401); // rsa_pkcs1_sha256
        writer.WriteUInt16(0x0503); // ecdsa_secp384r1_sha384
        writer.WriteUInt16(0x0805); // rsa_pss_rsae_sha384
        writer.WriteUInt16(0x0501); // rsa_pkcs1_sha384
        writer.WriteUInt16(0x0806); // rsa_pss_rsae_sha512
        writer.WriteUInt16(0x0601); // rsa_pkcs1_sha512
        writer.EndVector(algorithms, 2);

        writer.EndVector(extension, 2);
    }

    private static void WriteSupportedVersions(TlsWriter writer)
    {
        writer.WriteUInt16(ExtensionSupportedVersions);
        int extension = writer.BeginVector16();

        int versions = writer.BeginVector8();
        writer.WriteUInt16(Tls13);
        writer.EndVector(versions, 1);

        writer.EndVector(extension, 2);
    }

    private static void WritePskKeyExchangeModes(TlsWriter writer)
    {
        writer.WriteUInt16(ExtensionPskKeyExchangeModes);
        int extension = writer.BeginVector16();

        int modes = writer.BeginVector8();
        writer.WriteByte(1); // psk_dhe_ke
        writer.EndVector(modes, 1);

        writer.EndVector(extension, 2);
    }

    private static void WriteKeyShare(TlsWriter writer, ReadOnlySpan<byte> publicKey)
    {
        writer.WriteUInt16(ExtensionKeyShare);
        int extension = writer.BeginVector16();

        int shares = writer.BeginVector16();
        writer.WriteUInt16(GroupX25519);
        int share = writer.BeginVector16();
        writer.Write(publicKey);
        writer.EndVector(share, 2);
        writer.EndVector(shares, 2);

        writer.EndVector(extension, 2);
    }

    private static void WriteAlpn(TlsWriter writer, IReadOnlyList<string> alpn)
    {
        writer.WriteUInt16(ExtensionAlpn);
        int extension = writer.BeginVector16();

        int list = writer.BeginVector16();
        foreach (string protocol in alpn)
        {
            int entry = writer.BeginVector8();
            writer.Write(Encoding.ASCII.GetBytes(protocol));
            writer.EndVector(entry, 1);
        }

        writer.EndVector(list, 2);
        writer.EndVector(extension, 2);
    }

    /// <summary>Wraps a handshake message in a TLS plaintext record.</summary>
    /// <param name="handshake">The handshake message.</param>
    public static byte[] ToRecord(ReadOnlySpan<byte> handshake)
    {
        byte[] record = new byte[5 + handshake.Length];
        record[0] = 0x16;   // handshake
        record[1] = 0x03;
        record[2] = 0x01;   // legacy record version
        record[3] = (byte)(handshake.Length >> 8);
        record[4] = (byte)handshake.Length;
        handshake.CopyTo(record.AsSpan(5));

        return record;
    }
}
