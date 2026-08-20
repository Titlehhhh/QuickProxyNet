using System.Security.Cryptography;
using QuickProxyNet.Reality.Managed;

namespace QuickProxyNet.Tests;

/// <summary>
/// Tests for the TLS 1.3 record layer: framing, buffering, and the in-place AEAD contract the
/// buffering depends on.
/// </summary>
/// <remarks>
/// <para>
/// The layer reads and writes through one buffer per direction, hands out records as slices of
/// that buffer, and seals and opens every record in place. None of that is visible from the
/// outside when the transport is friendly — which is exactly why the tests here are unfriendly:
/// a transport that returns one byte at a time, a transport that returns four records at once,
/// and a peer that lies about its lengths.
/// </para>
/// <para>
/// A paired writer and reader share a traffic secret and therefore a sequence number, so they
/// stay in lockstep for the length of a test — the same construction the benchmarks use, and for
/// the same reason: a record's nonce cannot be rewound.
/// </para>
/// </remarks>
public class TlsRecordStreamTest
{
    private const ushort Aes128Gcm = 0x1301;
    private const ushort Aes256Gcm = 0x1302;
    private const ushort ChaCha20 = 0x1303;

    /// <summary>A transport that yields at most <paramref name="chunk"/> bytes per read.</summary>
    /// <remarks>
    /// The record layer's whole reason for existing is that a record does not arrive in one
    /// piece. A one-byte drip is the extreme of that, and it is the case where an off-by-one in
    /// the buffer bookkeeping shows up as a hang or as a record made of two other records.
    /// </remarks>
    private sealed class DripStream(byte[] data, int chunk) : Stream
    {
        private int _position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => data.Length;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int take = Math.Min(Math.Min(chunk, buffer.Length), data.Length - _position);
            data.AsSpan(_position, take).CopyTo(buffer);
            _position += take;

            return take;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            new(Read(buffer.Span));

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>Counts how many times the transport was asked to write.</summary>
    /// <remarks>
    /// Only the asynchronous overload is counted, and only that one: MemoryStream implements it
    /// by calling its own synchronous <c>Write</c>, so counting both would count every write
    /// twice.
    /// </remarks>
    private sealed class CountingStream : MemoryStream
    {
        public int Writes { get; private set; }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Writes++;
            return base.WriteAsync(buffer, cancellationToken);
        }
    }

    private static TlsCipherSuite Suite(ushort id) =>
        TlsCipherSuite.FromId(id) ?? throw new NotSupportedException($"Suite {id:x4} is unavailable here.");

    private static byte[] Secret(TlsCipherSuite suite)
    {
        byte[] secret = new byte[suite.HashLength];
        RandomNumberGenerator.Fill(secret);

        return secret;
    }

    private static byte[] Payload(int length)
    {
        byte[] payload = new byte[length];
        RandomNumberGenerator.Fill(payload);

        return payload;
    }

    public static TheoryData<ushort> Suites()
    {
        var suites = new TheoryData<ushort> { Aes128Gcm, Aes256Gcm };

        if (ChaCha20Poly1305.IsSupported)
            suites.Add(ChaCha20);

        return suites;
    }

    /// <summary>Sealing and opening a record returns exactly what went in, for every suite.</summary>
    /// <remarks>
    /// A paired protection, because the sequence number advances on both sides: the opener has to
    /// be a second instance built from the same traffic secret, at the same record number, which
    /// is the same thing a real peer is.
    /// </remarks>
    [Theory]
    [MemberData(nameof(Suites))]
    public void Protect_ThenUnprotect_ReturnsThePlaintext(ushort id)
    {
        TlsCipherSuite suite = Suite(id);
        byte[] secret = Secret(suite);
        byte[] plaintext = Payload(4096);
        byte[] header = [23, 3, 3, 0x10, 0x10];

        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TlsCipherSuite.TagLength];
        using (var sealer = new TlsRecordProtection(suite, secret))
            sealer.Protect(plaintext, ciphertext, tag, header);

        Assert.NotEqual(plaintext, ciphertext);

        byte[] opened = new byte[plaintext.Length];
        using (var opener = new TlsRecordProtection(suite, secret))
            opener.Unprotect(ciphertext, tag, opened, header);

        Assert.Equal(plaintext, opened);
    }

    /// <summary>An encrypted record survives the round trip, whatever the suite.</summary>
    [Theory]
    [MemberData(nameof(Suites))]
    public async Task EncryptedRecord_RoundTrips(ushort id)
    {
        TlsCipherSuite suite = Suite(id);
        byte[] secret = Secret(suite);
        byte[] payload = Payload(1234);

        var wire = new MemoryStream();
        using (var writer = new TlsRecordStream(wire) { Write = new TlsRecordProtection(suite, secret) })
            await writer.WriteAsync(TlsContentType.Handshake, payload, CancellationToken.None);

        using var reader = new TlsRecordStream(new MemoryStream(wire.ToArray()))
        {
            Read = new TlsRecordProtection(suite, secret)
        };

        TlsRecordStream.Record record = await reader.ReadAsync(CancellationToken.None);

        // The outer type on the wire is application_data; the real type rides inside the sealed
        // record, which is the whole point of TLS 1.3's inner content type.
        Assert.Equal(TlsContentType.ApplicationData, (TlsContentType)wire.ToArray()[0]);
        Assert.Equal(TlsContentType.Handshake, record.Type);
        Assert.Equal(payload, record.Payload.ToArray());
    }

    /// <summary>
    /// A record split across many transport reads is reassembled; several records in one read are
    /// handed out one at a time.
    /// </summary>
    /// <remarks>
    /// Both directions of the same bookkeeping: <c>chunk</c> of 1 forces every record to be
    /// assembled from fragments, and a chunk larger than a record forces several records out of
    /// one buffer without a transport read in between.
    /// </remarks>
    [Theory]
    [InlineData(1)]
    [InlineData(7)]
    [InlineData(64 * 1024)]
    public async Task Records_SurviveAnyTransportChunking(int chunk)
    {
        TlsCipherSuite suite = Suite(Aes128Gcm);
        byte[] secret = Secret(suite);
        byte[][] payloads =
        [
            Payload(1),
            Payload(300),
            Payload(TlsRecordStream.MaxPlaintext),
            Payload(5000)
        ];

        var wire = new MemoryStream();
        using (var writer = new TlsRecordStream(wire) { Write = new TlsRecordProtection(suite, secret) })
        {
            foreach (byte[] payload in payloads)
                await writer.WriteAsync(
                    TlsContentType.ApplicationData, payload, CancellationToken.None);
        }

        using var reader = new TlsRecordStream(new DripStream(wire.ToArray(), chunk))
        {
            Read = new TlsRecordProtection(suite, secret)
        };

        foreach (byte[] payload in payloads)
        {
            TlsRecordStream.Record record = await reader.ReadAsync(CancellationToken.None);

            Assert.Equal(TlsContentType.ApplicationData, record.Type);
            Assert.Equal(payload, record.Payload.ToArray());
        }
    }

    /// <summary>An unencrypted record keeps the framing a ClientHello needs.</summary>
    /// <remarks>
    /// The legacy version byte is 0x0301 for a handshake record and 0x0303 otherwise. It is
    /// meaningless to TLS 1.3 and load-bearing to REALITY: it is part of what a fingerprint
    /// matches on, so a record layer that "corrected" it would change how the client looks.
    /// </remarks>
    [Fact]
    public async Task UnencryptedRecord_KeepsItsLegacyVersion()
    {
        byte[] payload = Payload(64);

        var wire = new MemoryStream();
        using (var writer = new TlsRecordStream(wire))
        {
            await writer.WriteAsync(TlsContentType.Handshake, payload, CancellationToken.None);
            await writer.WriteAsync(
                TlsContentType.ChangeCipherSpec, new byte[] { 1 }, CancellationToken.None);
        }

        byte[] bytes = wire.ToArray();
        Assert.Equal(22, bytes[0]);
        Assert.Equal(3, bytes[1]);
        Assert.Equal(1, bytes[2]);
        Assert.Equal(payload.Length, (bytes[3] << 8) | bytes[4]);

        byte[] changeCipherSpec = bytes.AsSpan(5 + payload.Length).ToArray();
        Assert.Equal(20, changeCipherSpec[0]);
        Assert.Equal(3, changeCipherSpec[2]);

        using var reader = new TlsRecordStream(new MemoryStream(bytes));
        TlsRecordStream.Record first = await reader.ReadAsync(CancellationToken.None);
        TlsRecordStream.Record second = await reader.ReadAsync(CancellationToken.None);

        Assert.Equal(TlsContentType.Handshake, first.Type);
        Assert.Equal(payload, first.Payload.ToArray());
        Assert.Equal(TlsContentType.ChangeCipherSpec, second.Type);
    }

    /// <summary>
    /// ChangeCipherSpec is handed back verbatim even once read protection is installed.
    /// </summary>
    [Fact]
    public async Task ChangeCipherSpec_IsNeverDecrypted()
    {
        TlsCipherSuite suite = Suite(Aes128Gcm);
        byte[] secret = Secret(suite);

        byte[] wire = [20, 3, 3, 0, 1, 1];

        using var reader = new TlsRecordStream(new MemoryStream(wire))
        {
            Read = new TlsRecordProtection(suite, secret)
        };

        TlsRecordStream.Record record = await reader.ReadAsync(CancellationToken.None);

        Assert.Equal(TlsContentType.ChangeCipherSpec, record.Type);
        Assert.Equal(new byte[] { 1 }, record.Payload.ToArray());
    }

    /// <summary>A record larger than the limit is refused on its header, before its body.</summary>
    [Fact]
    public async Task OversizedRecord_IsRefused()
    {
        // A length one over the ciphertext limit, and no body at all behind it: the refusal has to
        // come from the header, or this hangs waiting for bytes the peer never sends.
        int length = TlsRecordStream.MaxCiphertext + 1;
        byte[] wire = [23, 3, 3, (byte)(length >> 8), (byte)length];

        using var reader = new TlsRecordStream(new MemoryStream(wire));

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await reader.ReadAsync(CancellationToken.None));
    }

    /// <summary>An encrypted record shorter than its own tag is refused.</summary>
    [Fact]
    public async Task RecordShorterThanItsTag_IsRefused()
    {
        TlsCipherSuite suite = Suite(Aes128Gcm);
        byte[] wire = [23, 3, 3, 0, 4, 1, 2, 3, 4];

        using var reader = new TlsRecordStream(new MemoryStream(wire))
        {
            Read = new TlsRecordProtection(suite, Secret(suite))
        };

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await reader.ReadAsync(CancellationToken.None));
    }

    /// <summary>A record that is all padding and no content type is refused.</summary>
    [Fact]
    public async Task RecordWithoutAContentType_IsRefused()
    {
        TlsCipherSuite suite = Suite(Aes128Gcm);
        byte[] secret = Secret(suite);

        // Sealed by hand, because the writer never produces one: the inner content type is the
        // last non-zero byte, so a plaintext of nothing but zeros has none.
        byte[] inner = new byte[8];
        byte[] wire = new byte[5 + inner.Length + TlsCipherSuite.TagLength];
        wire[0] = 23;
        wire[1] = 3;
        wire[2] = 3;
        wire[3] = (byte)((inner.Length + TlsCipherSuite.TagLength) >> 8);
        wire[4] = (byte)(inner.Length + TlsCipherSuite.TagLength);

        using (var protection = new TlsRecordProtection(suite, secret))
            protection.Protect(
                inner,
                wire.AsSpan(5, inner.Length),
                wire.AsSpan(5 + inner.Length, TlsCipherSuite.TagLength),
                wire.AsSpan(0, 5));

        using var reader = new TlsRecordStream(new MemoryStream(wire))
        {
            Read = new TlsRecordProtection(suite, secret)
        };

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await reader.ReadAsync(CancellationToken.None));
    }

    /// <summary>A tampered record does not open.</summary>
    [Fact]
    public async Task TamperedRecord_FailsItsTagCheck()
    {
        TlsCipherSuite suite = Suite(Aes128Gcm);
        byte[] secret = Secret(suite);

        var wire = new MemoryStream();
        using (var writer = new TlsRecordStream(wire) { Write = new TlsRecordProtection(suite, secret) })
            await writer.WriteAsync(
                TlsContentType.ApplicationData, Payload(256), CancellationToken.None);

        byte[] bytes = wire.ToArray();
        bytes[10] ^= 0xff;

        using var reader = new TlsRecordStream(new MemoryStream(bytes))
        {
            Read = new TlsRecordProtection(suite, secret)
        };

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(async () =>
            await reader.ReadAsync(CancellationToken.None));
    }

    /// <summary>A transport that ends mid-record reports end of stream.</summary>
    /// <remarks>
    /// <see cref="RealityTlsStream"/> catches <see cref="EndOfStreamException"/> and reports it to
    /// its caller as a clean end of stream, so this is the exception type the layer above is
    /// written against — not an implementation detail of how the bytes were read.
    /// </remarks>
    [Fact]
    public async Task TruncatedRecord_ReportsEndOfStream()
    {
        byte[] wire = [22, 3, 1, 0, 16, 1, 2, 3];

        using var reader = new TlsRecordStream(new MemoryStream(wire));

        await Assert.ThrowsAsync<EndOfStreamException>(async () =>
            await reader.ReadAsync(CancellationToken.None));
    }

    /// <summary>
    /// Application data larger than one record becomes several records — in one transport write.
    /// </summary>
    /// <remarks>
    /// The record split is RFC 8446 §5.1 and not negotiable. The single write is the point of the
    /// staging buffer: 40 KiB of payload is three records, and sending those separately would be
    /// three writes and three flushes to satisfy one caller.
    /// </remarks>
    [Fact]
    public async Task LargeApplicationWrite_IsThreeRecordsInOneWrite()
    {
        TlsCipherSuite suite = Suite(Aes128Gcm);
        byte[] secret = Secret(suite);
        byte[] payload = Payload(40 * 1024);

        var wire = new CountingStream();
        using (var writer = new TlsRecordStream(wire) { Write = new TlsRecordProtection(suite, secret) })
            await writer.WriteApplicationDataAsync(payload, CancellationToken.None);

        Assert.Equal(1, wire.Writes);

        using var reader = new TlsRecordStream(new MemoryStream(wire.ToArray()))
        {
            Read = new TlsRecordProtection(suite, secret)
        };

        var received = new List<byte>();
        var lengths = new List<int>();
        while (received.Count < payload.Length)
        {
            TlsRecordStream.Record record = await reader.ReadAsync(CancellationToken.None);

            Assert.Equal(TlsContentType.ApplicationData, record.Type);
            lengths.Add(record.Payload.Length);
            received.AddRange(record.Payload.ToArray());
        }

        Assert.Equal(
            new[] { TlsRecordStream.MaxPlaintext, TlsRecordStream.MaxPlaintext, (40 * 1024) - (2 * TlsRecordStream.MaxPlaintext) },
            lengths);
        Assert.Equal(payload, received);
    }

    /// <summary>A write past the staging buffer takes more than one write, and still round-trips.</summary>
    /// <remarks>
    /// The staging buffer holds three full-size records, so a 1 MiB write cannot go out in one
    /// piece — what matters is that the payload comes back whole across the batches, which is the
    /// case the batching loop gets wrong if it forgets what it has already staged.
    /// </remarks>
    [Fact]
    public async Task ApplicationWrite_LargerThanTheStagingBuffer_RoundTrips()
    {
        TlsCipherSuite suite = Suite(Aes128Gcm);
        byte[] secret = Secret(suite);
        byte[] payload = Payload(1024 * 1024);

        var wire = new CountingStream();
        using (var writer = new TlsRecordStream(wire) { Write = new TlsRecordProtection(suite, secret) })
            await writer.WriteApplicationDataAsync(payload, CancellationToken.None);

        Assert.InRange(wire.Writes, 2, 64);

        using var reader = new TlsRecordStream(new MemoryStream(wire.ToArray()))
        {
            Read = new TlsRecordProtection(suite, secret)
        };

        var received = new List<byte>();
        while (received.Count < payload.Length)
        {
            TlsRecordStream.Record record = await reader.ReadAsync(CancellationToken.None);
            received.AddRange(record.Payload.ToArray());
        }

        Assert.Equal(payload, received);
    }

    /// <summary>
    /// A record that has been read stays intact while the same connection writes.
    /// </summary>
    /// <remarks>
    /// Reading and writing share nothing, and this is the test that says so. A relay holds the
    /// record it just read while it sends something else — the ordinary full-duplex pattern — so
    /// a staging buffer shared between the two directions would corrupt the payload in the
    /// reader's hand, on exactly the traffic a proxy exists to carry.
    /// </remarks>
    [Fact]
    public async Task ReadPayload_SurvivesAnInterleavedWrite()
    {
        TlsCipherSuite suite = Suite(Aes128Gcm);
        byte[] inboundSecret = Secret(suite);
        byte[] outboundSecret = Secret(suite);
        byte[] incoming = Payload(4096);

        var peer = new MemoryStream();
        using (var peerWriter = new TlsRecordStream(peer) { Write = new TlsRecordProtection(suite, inboundSecret) })
            await peerWriter.WriteAsync(TlsContentType.ApplicationData, incoming, CancellationToken.None);

        var wire = new CountingStream();
        wire.Write(peer.ToArray());
        wire.Position = 0;

        using var connection = new TlsRecordStream(wire)
        {
            Read = new TlsRecordProtection(suite, inboundSecret),
            Write = new TlsRecordProtection(suite, outboundSecret)
        };

        TlsRecordStream.Record held = await connection.ReadAsync(CancellationToken.None);

        wire.Position = wire.Length;
        await connection.WriteApplicationDataAsync(Payload(40 * 1024), CancellationToken.None);

        Assert.Equal(incoming, held.Payload.ToArray());
    }

    /// <summary>
    /// A record handed out stays intact while the caller holds it, across the read that follows.
    /// </summary>
    /// <remarks>
    /// The payload is a slice of the layer's own buffer, promised valid until the next read — and
    /// the next read is what compacts that buffer. This pins the boundary: consume the record,
    /// then read again, and the bytes must still be the ones that arrived.
    /// </remarks>
    [Fact]
    public async Task PayloadStaysValid_UntilTheNextRead()
    {
        TlsCipherSuite suite = Suite(Aes128Gcm);
        byte[] secret = Secret(suite);
        byte[] first = Payload(2048);
        byte[] second = Payload(2048);

        var wire = new MemoryStream();
        using (var writer = new TlsRecordStream(wire) { Write = new TlsRecordProtection(suite, secret) })
        {
            await writer.WriteAsync(TlsContentType.ApplicationData, first, CancellationToken.None);
            await writer.WriteAsync(TlsContentType.ApplicationData, second, CancellationToken.None);
        }

        using var reader = new TlsRecordStream(new DripStream(wire.ToArray(), 700))
        {
            Read = new TlsRecordProtection(suite, secret)
        };

        TlsRecordStream.Record held = await reader.ReadAsync(CancellationToken.None);
        Assert.Equal(first, held.Payload.ToArray());

        TlsRecordStream.Record next = await reader.ReadAsync(CancellationToken.None);
        Assert.Equal(second, next.Payload.ToArray());
    }
}
