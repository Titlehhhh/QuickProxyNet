using QuickProxyNet.Tests.Helpers;

// CA2022 ("avoid inexact reads") warns whenever a single ReadAsync is expected to fill a
// buffer. Partial reads are exactly what these tests exercise.
#pragma warning disable CA2022

namespace QuickProxyNet.Tests;

/// <summary>
/// Round trips through <see cref="ShadowsocksStream"/> in chunks of random length, both when
/// handing payload to <c>Write</c> and when feeding wire bytes into <c>Read</c>.
/// </summary>
/// <remarks>
/// <para>
/// A cipher stream that is tested with one call carrying the whole buffer proves little: every
/// interesting bug lives at a boundary — a chunk split across two writes, a length block split
/// across two reads, a caller's buffer smaller than the chunk, a chunk larger than <c>0x3FFF</c>
/// that has to be cut. So every case here slices with a seeded <see cref="Random"/> and asserts
/// the bytes come out identical and the chunk count is what the slicing predicts.
/// </para>
/// <para>
/// The peer is a second <see cref="ShadowsocksStream"/> keyed with the same master key: its read
/// direction derives the subkey from whatever salt arrives, exactly as a server does, so the
/// writer's output is read back through the code under test rather than through a helper.
/// </para>
/// </remarks>
public class ShadowsocksStreamTest
{
    private const string Password = "quickproxynet-test-password";
    private const int PayloadSize = 100_000;

    private static byte[] MasterKey(ShadowsocksMethod method)
    {
        byte[] key = new byte[ShadowsocksCipher.KeySize(method)];
        ShadowsocksCipher.DeriveMasterKey(Password, key);
        return key;
    }

    private static byte[] Salt(ShadowsocksMethod method, byte seed)
    {
        byte[] salt = new byte[ShadowsocksCipher.SaltSize(method)];
        for (int i = 0; i < salt.Length; i++)
            salt[i] = (byte)(seed + i * 7);
        return salt;
    }

    private static int ExpectedChunks(int writeLength) =>
        (writeLength + ShadowsocksStream.MaxPayloadSize - 1) / ShadowsocksStream.MaxPayloadSize;

    /// <summary>Writes <paramref name="payload"/> in random slices; returns the chunks this must produce.</summary>
    private static async Task<int> WriteInRandomSlicesAsync(Stream stream, byte[] payload, Random rng, int maxSlice)
    {
        int chunks = 0;
        int offset = 0;
        while (offset < payload.Length)
        {
            int count = Math.Min(rng.Next(1, maxSlice + 1), payload.Length - offset);
            await stream.WriteAsync(payload.AsMemory(offset, count));
            chunks += ExpectedChunks(count);
            offset += count;
        }

        return chunks;
    }

    /// <summary>Reads exactly <paramref name="length"/> bytes with random-sized buffers.</summary>
    private static async Task<byte[]> ReadInRandomSlicesAsync(Stream stream, int length, Random rng, int maxSlice)
    {
        byte[] received = new byte[length];
        int offset = 0;
        while (offset < length)
        {
            int want = Math.Min(rng.Next(1, maxSlice + 1), length - offset);
            int read = await stream.ReadAsync(received.AsMemory(offset, want));
            Assert.True(read > 0, "a Read returned 0 before the payload was complete");
            Assert.True(read <= want);
            offset += read;
        }

        return received;
    }

    [Theory]
    [InlineData("aes-256-gcm", 1)]
    [InlineData("aes-256-gcm", 2)]
    [InlineData("aes-256-gcm", 3)]
    [InlineData("aes-128-gcm", 4)]
    [InlineData("aes-192-gcm", 5)]
    [ChaCha20InlineData("chacha20-ietf-poly1305", 6)]
    [ChaCha20InlineData("chacha20-ietf-poly1305", 7)]
    public async Task ClientToServer_RandomWriteSlices_RandomReadSlices_RoundTrips(string name, int seed)
    {
        ShadowsocksMethod method = ShadowsocksCipher.Resolve(name);
        var rng = new Random(seed);
        byte[] payload = new byte[PayloadSize];
        rng.NextBytes(payload);

        // Client side: writes in slices of 1..40 000 bytes, so some are cut into 0x3FFF chunks
        // and some are tiny.
        var outbound = new DuplexTestStream([]);
        var client = new ShadowsocksStream(outbound, method, MasterKey(method), Salt(method, 0x11), leaveInnerOpen: true);
        int chunks = await WriteInRandomSlicesAsync(client, payload, rng, maxSlice: 40_000);

        byte[] wire = outbound.Written;
        Assert.Equal(2UL * (ulong)chunks, client.WriteNonceCounter);
        Assert.Equal(ShadowsocksCipher.SaltSize(method) + payload.Length + 34 * chunks, wire.Length);

        // Server side: the wire arrives in random slices of 1..5 000 bytes, so salt, length block
        // and payload all get split at arbitrary points; the caller reads with random buffers.
        var inbound = new RandomSliceStream(wire, new Random(seed + 100), maxSlice: 5_000);
        var server = new ShadowsocksStream(inbound, method, MasterKey(method), Salt(method, 0x22), leaveInnerOpen: true);
        byte[] received = await ReadInRandomSlicesAsync(server, payload.Length, new Random(seed + 200), maxSlice: 50_000);

        Assert.Equal(payload, received);
        Assert.Equal(2UL * (ulong)chunks, server.ReadNonceCounter);
        Assert.True(server.IsServerSaltRead);

        // Everything consumed: the FIN lands exactly on a chunk boundary.
        Assert.Equal(0, await server.ReadAsync(new byte[16]));
        Assert.True(server.IsReadCompleted);
    }

    [Theory]
    [InlineData("aes-256-gcm", 11)]
    [InlineData("aes-128-gcm", 12)]
    [ChaCha20InlineData("chacha20-ietf-poly1305", 13)]
    public async Task ServerToClient_RandomWriteSlices_RandomReadSlices_RoundTrips(string name, int seed)
    {
        // The other direction: the "server" stream writes with its own salt, the "client" stream
        // reads it. Same code paths in mirror; independent counters and subkeys.
        ShadowsocksMethod method = ShadowsocksCipher.Resolve(name);
        var rng = new Random(seed);
        byte[] payload = new byte[PayloadSize];
        rng.NextBytes(payload);

        var outbound = new DuplexTestStream([]);
        var server = new ShadowsocksStream(outbound, method, MasterKey(method), Salt(method, 0x33), leaveInnerOpen: true);
        int chunks = await WriteInRandomSlicesAsync(server, payload, rng, maxSlice: 20_000);

        var inbound = new RandomSliceStream(outbound.Written, new Random(seed + 100), maxSlice: 700);
        var client = new ShadowsocksStream(inbound, method, MasterKey(method), Salt(method, 0x44), leaveInnerOpen: true);

        // The client has written nothing: its own salt is still pending and its write counter is
        // untouched while it reads.
        byte[] received = await ReadInRandomSlicesAsync(client, payload.Length, new Random(seed + 200), maxSlice: 3_000);

        Assert.Equal(payload, received);
        Assert.Equal(2UL * (ulong)chunks, client.ReadNonceCounter);
        Assert.Equal(0UL, client.WriteNonceCounter);
        Assert.Equal(0, await client.ReadAsync(new byte[16]));
    }

    [Fact]
    public async Task BothDirections_OnOneStreamPair_KeepIndependentCounters()
    {
        ShadowsocksMethod method = ShadowsocksMethod.Aes256Gcm;
        var rng = new Random(21);

        byte[] request = new byte[30_000];
        byte[] response = new byte[70_000];
        rng.NextBytes(request);
        rng.NextBytes(response);

        // Client writes the request; server reads it and writes the response; client reads it.
        var toServer = new DuplexTestStream([]);
        var client = new ShadowsocksStream(toServer, method, MasterKey(method), Salt(method, 0x55), leaveInnerOpen: true);
        int requestChunks = await WriteInRandomSlicesAsync(client, request, rng, maxSlice: 9_000);

        var toClient = new DuplexTestStream([]);
        var serverReader = new ShadowsocksStream(
            new RandomSliceStream(toServer.Written, new Random(22), maxSlice: 1_500),
            method, MasterKey(method), Salt(method, 0x66), leaveInnerOpen: true);
        Assert.Equal(request, await ReadInRandomSlicesAsync(serverReader, request.Length, new Random(23), maxSlice: 8_000));

        var serverWriter = new ShadowsocksStream(toClient, method, MasterKey(method), Salt(method, 0x66), leaveInnerOpen: true);
        int responseChunks = await WriteInRandomSlicesAsync(serverWriter, response, rng, maxSlice: 25_000);

        var clientReader = new ShadowsocksStream(
            new RandomSliceStream(toClient.Written, new Random(24), maxSlice: 2_000),
            method, MasterKey(method), Salt(method, 0x55), leaveInnerOpen: true);
        Assert.Equal(response, await ReadInRandomSlicesAsync(clientReader, response.Length, new Random(25), maxSlice: 60_000));

        Assert.Equal(2UL * (ulong)requestChunks, client.WriteNonceCounter);
        Assert.Equal(2UL * (ulong)requestChunks, serverReader.ReadNonceCounter);
        Assert.Equal(2UL * (ulong)responseChunks, serverWriter.WriteNonceCounter);
        Assert.Equal(2UL * (ulong)responseChunks, clientReader.ReadNonceCounter);
    }

    [Fact]
    public void SyncOverloads_RandomSlices_RoundTrip()
    {
        ShadowsocksMethod method = ShadowsocksMethod.Aes128Gcm;
        var rng = new Random(31);
        byte[] payload = new byte[40_000];
        rng.NextBytes(payload);

        var outbound = new DuplexTestStream([]);
        var writer = new ShadowsocksStream(outbound, method, MasterKey(method), Salt(method, 0x77), leaveInnerOpen: true);
        int offset = 0;
        while (offset < payload.Length)
        {
            int count = Math.Min(rng.Next(1, 20_000), payload.Length - offset);
            if ((offset & 1) == 0)
                writer.Write(payload.AsSpan(offset, count));
            else
                writer.Write(payload, offset, count);
            offset += count;
        }

        var reader = new ShadowsocksStream(
            new RandomSliceStream(outbound.Written, new Random(32), maxSlice: 900),
            method, MasterKey(method), Salt(method, 0x88), leaveInnerOpen: true);

        byte[] received = new byte[payload.Length];
        offset = 0;
        while (offset < received.Length)
        {
            int want = Math.Min(rng.Next(1, 7_000), received.Length - offset);
            int read = (offset & 1) == 0
                ? reader.Read(received.AsSpan(offset, want))
                : reader.Read(received, offset, want);
            Assert.True(read > 0);
            offset += read;
        }

        Assert.Equal(payload, received);
        Assert.Equal(0, reader.Read(new byte[8], 0, 8));
    }

    [Fact]
    public async Task SyncWriteSpan_RandomSlices_ReadByTheAsyncReader_RoundTrips()
    {
        // The synchronous Write seals straight into the send buffer and calls the transport's
        // synchronous Write: no rented copy, no blocking on the async path. Its wire must be what
        // the async reader expects, and every Write of at most one chunk must be one transport write.
        ShadowsocksMethod method = ShadowsocksMethod.Aes256Gcm;
        var rng = new Random(41);
        byte[] payload = new byte[PayloadSize];
        rng.NextBytes(payload);

        var sink = new CountingSink();
        var writer = new ShadowsocksStream(sink, method, MasterKey(method), Salt(method, 0x99), leaveInnerOpen: true);
        int chunks = 0;
        int writes = 0;
        int offset = 0;
        while (offset < payload.Length)
        {
            int count = Math.Min(rng.Next(1, 40_001), payload.Length - offset);
            writer.Write(payload.AsSpan(offset, count));
            chunks += ExpectedChunks(count);
            writes++;
            offset += count;
        }

        Assert.Equal(writes, sink.WriteCount); // 40 000 bytes are at most three chunks: always one run
        Assert.Equal(2UL * (ulong)chunks, writer.WriteNonceCounter);

        var reader = new ShadowsocksStream(
            new RandomSliceStream(sink.Written, new Random(42), maxSlice: 3_000),
            method, MasterKey(method), Salt(method, 0xAA), leaveInnerOpen: true);
        Assert.Equal(payload, await ReadInRandomSlicesAsync(reader, payload.Length, new Random(43), maxSlice: 20_000));
        Assert.Equal(0, await reader.ReadAsync(new byte[16]));
    }

    [Fact]
    public async Task WriteAsync_SealsConsecutiveChunksIntoOneTransportWrite()
    {
        ShadowsocksMethod method = ShadowsocksMethod.Aes256Gcm;
        var sink = new CountingSink();
        var stream = new ShadowsocksStream(sink, method, MasterKey(method), Salt(method, 0x12), leaveInnerOpen: true);

        // CopyToAsync's default buffer: six chunks (5 × 16 383 + 5), salt included, in ONE write.
        await stream.WriteAsync(new byte[81_920]);
        Assert.Equal(1, sink.WriteCount);
        Assert.Equal(12UL, stream.WriteNonceCounter);
        Assert.Equal(32 + 81_920 + 6 * 34, sink.Written.Length);

        // 1 MiB is 65 chunks; the send buffer takes seven per write (the 128 KiB pool bucket holds
        // the salt plus seven full chunks), so ten writes — not sixty-five.
        await stream.WriteAsync(new byte[1 << 20]);
        Assert.Equal(11, sink.WriteCount);
        Assert.Equal(2UL * (6 + 65), stream.WriteNonceCounter);
        Assert.Equal(32 + 81_920 + 6 * 34 + (1 << 20) + 65 * 34, sink.Written.Length);
    }

    [Fact]
    public async Task WriteAsync_Coalesced_ProducesTheSameWireAsChunkByChunk()
    {
        // Coalescing changes how many transport writes carry the bytes, never the bytes: the
        // chunk boundaries and the nonce sequence are what they were, so one WriteAsync and the
        // same payload fed through WriteChunkAsync slice by slice must produce identical wires.
        ShadowsocksMethod method = ShadowsocksMethod.Aes128Gcm;
        byte[] payload = new byte[4 * ShadowsocksStream.MaxPayloadSize + 123];
        new Random(51).NextBytes(payload);

        var oneCall = new CountingSink();
        await new ShadowsocksStream(oneCall, method, MasterKey(method), Salt(method, 0x13), leaveInnerOpen: true)
            .WriteAsync(payload);
        Assert.Equal(1, oneCall.WriteCount);

        var chunkByChunk = new CountingSink();
        var stream = new ShadowsocksStream(chunkByChunk, method, MasterKey(method), Salt(method, 0x13), leaveInnerOpen: true);
        for (int offset = 0; offset < payload.Length; offset += ShadowsocksStream.MaxPayloadSize)
        {
            int count = Math.Min(ShadowsocksStream.MaxPayloadSize, payload.Length - offset);
            await stream.WriteChunkAsync(payload.AsMemory(offset, count));
        }

        Assert.Equal(5, chunkByChunk.WriteCount);
        Assert.Equal(chunkByChunk.Written, oneCall.Written);
    }

    [Fact]
    public async Task ReadAsync_OpensExactlyOneChunkPerCall_FromAWindowHoldingSeveral()
    {
        // The reader takes whatever the transport has — here five chunks and the salt in one
        // transport read — but opens only the chunk the caller asked for: the nonce advances by
        // two per Read, and later Reads are served from the window without touching the transport.
        ShadowsocksMethod method = ShadowsocksMethod.Aes256Gcm;
        var outbound = new DuplexTestStream([]);
        var writer = new ShadowsocksStream(outbound, method, MasterKey(method), Salt(method, 0x14), leaveInnerOpen: true);
        for (int i = 0; i < 5; i++)
            await writer.WriteAsync(new byte[100 + i]);

        var transport = new ScriptedDuplexStream();
        transport.Enqueue(outbound.Written);
        var reader = new ShadowsocksStream(transport, method, MasterKey(method), Salt(method, 0x15), leaveInnerOpen: true);

        byte[] buffer = new byte[1024];
        for (int i = 0; i < 5; i++)
        {
            Assert.Equal(100 + i, await reader.ReadAsync(buffer));
            Assert.Equal(2UL * (ulong)(i + 1), reader.ReadNonceCounter);
            Assert.Equal(1, transport.ReadCount);
        }

        // Only the FIN needs another transport read.
        Assert.Equal(0, await reader.ReadAsync(buffer));
        Assert.Equal(2, transport.ReadCount);
        Assert.True(reader.IsReadCompleted);
    }

    [Fact]
    public async Task ReadAsync_OneByteTransportReads_OneByteCallerBuffer_AcrossAMaxChunk()
    {
        // Both extremes at once: the transport hands over one byte per read, so the salt, the
        // length block and a 16 399-byte payload+tag each take many fills, and the caller wants one
        // byte per Read, so the whole chunk is opened once and drained from the leftover buffer.
        ShadowsocksMethod method = ShadowsocksMethod.Aes128Gcm;
        byte[] payload = new byte[ShadowsocksStream.MaxPayloadSize];
        new Random(61).NextBytes(payload);

        var outbound = new DuplexTestStream([]);
        await new ShadowsocksStream(outbound, method, MasterKey(method), Salt(method, 0x16), leaveInnerOpen: true)
            .WriteAsync(payload);

        var reader = new ShadowsocksStream(
            new DuplexTestStream(outbound.Written, maxReadSize: 1),
            method, MasterKey(method), Salt(method, 0x17), leaveInnerOpen: true);

        byte[] received = new byte[payload.Length];
        byte[] one = new byte[1];
        for (int i = 0; i < received.Length; i++)
        {
            Assert.Equal(1, await reader.ReadAsync(one));
            received[i] = one[0];
            Assert.Equal(2UL, reader.ReadNonceCounter); // opened once, on the first Read
        }

        Assert.Equal(payload, received);
        Assert.Equal(0, await reader.ReadAsync(one));
    }

    [Fact]
    public async Task ReadAsync_TransportSlicesLargerThanTheWindow_RoundTrips()
    {
        // Slices up to 100 000 bytes against a 32 KiB window: every transport read is bounded by
        // the free space behind the unparsed tail, chunks straddle the end of the buffer and are
        // compacted to the front, and nothing is lost or duplicated.
        ShadowsocksMethod method = ShadowsocksMethod.Aes256Gcm;
        var rng = new Random(71);
        byte[] payload = new byte[PayloadSize];
        rng.NextBytes(payload);

        var outbound = new DuplexTestStream([]);
        var writer = new ShadowsocksStream(outbound, method, MasterKey(method), Salt(method, 0x18), leaveInnerOpen: true);
        int chunks = await WriteInRandomSlicesAsync(writer, payload, rng, maxSlice: 30_000);

        var reader = new ShadowsocksStream(
            new RandomSliceStream(outbound.Written, new Random(72), maxSlice: 100_000),
            method, MasterKey(method), Salt(method, 0x19), leaveInnerOpen: true);
        Assert.Equal(payload, await ReadInRandomSlicesAsync(reader, payload.Length, new Random(73), maxSlice: 2_000));
        Assert.Equal(2UL * (ulong)chunks, reader.ReadNonceCounter);
        Assert.Equal(0, await reader.ReadAsync(new byte[16]));
    }

    [Fact]
    public async Task Write_EmptyBuffer_EmitsNothing_NotEvenTheSalt()
    {
        ShadowsocksMethod method = ShadowsocksMethod.Aes256Gcm;
        var outbound = new DuplexTestStream([]);
        var stream = new ShadowsocksStream(outbound, method, MasterKey(method), Salt(method, 1), leaveInnerOpen: true);

        await stream.WriteAsync(ReadOnlyMemory<byte>.Empty);

        Assert.Empty(outbound.Written);
        Assert.Equal(0UL, stream.WriteNonceCounter);

        // The salt then travels with the first real chunk, in one write.
        await stream.WriteAsync("x"u8.ToArray());
        Assert.Equal(32 + 35, outbound.Written.Length);
    }

    [Fact]
    public async Task Write_LargeBuffer_SplitsAtTheChunkCap()
    {
        ShadowsocksMethod method = ShadowsocksMethod.Aes256Gcm;
        var outbound = new DuplexTestStream([]);
        var stream = new ShadowsocksStream(outbound, method, MasterKey(method), Salt(method, 2), leaveInnerOpen: true);

        await stream.WriteAsync(new byte[3 * ShadowsocksStream.MaxPayloadSize + 5]);

        Assert.Equal(8UL, stream.WriteNonceCounter); // 4 chunks
        Assert.Equal(32 + (3 * (ShadowsocksStream.MaxPayloadSize + 34)) + (5 + 34), outbound.Written.Length);
    }

    [Fact]
    public async Task WriteChunk_AboveTheCap_IsRefused()
    {
        ShadowsocksMethod method = ShadowsocksMethod.Aes256Gcm;
        var stream = new ShadowsocksStream(new DuplexTestStream([]), method, MasterKey(method), Salt(method, 3), leaveInnerOpen: true);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
            await stream.WriteChunkAsync(new byte[ShadowsocksStream.MaxPayloadSize + 1]));
    }

    [Fact]
    public async Task ReadAndWrite_HonorCancellation()
    {
        ShadowsocksMethod method = ShadowsocksMethod.Aes256Gcm;
        var stream = new ShadowsocksStream(new DuplexTestStream(new byte[64]), method, MasterKey(method), Salt(method, 4), leaveInnerOpen: true);

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await stream.ReadAsync(new byte[64], cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await stream.WriteAsync("hello"u8.ToArray(), cts.Token));
    }

    [Fact]
    public async Task Dispose_DisposesTheInnerStreamUnlessAskedNotTo_AndRejectsLaterUse()
    {
        ShadowsocksMethod method = ShadowsocksMethod.Aes256Gcm;

        var owned = new DuplexTestStream([]);
        var stream = new ShadowsocksStream(owned, method, MasterKey(method), Salt(method, 5));
        await stream.DisposeAsync();
        await stream.DisposeAsync();
        Assert.Equal(1, owned.DisposeCount);
        Assert.False(stream.CanRead);
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await stream.ReadAsync(new byte[8]));
        await Assert.ThrowsAsync<ObjectDisposedException>(async () => await stream.WriteAsync(new byte[8]));

        var borrowed = new DuplexTestStream([]);
        new ShadowsocksStream(borrowed, method, MasterKey(method), Salt(method, 6), leaveInnerOpen: true).Dispose();
        Assert.Equal(0, borrowed.DisposeCount);
    }

    [Fact]
    public void Constructor_RejectsWrongSizesAndNull()
    {
        var transport = new DuplexTestStream([]);
        byte[] key32 = MasterKey(ShadowsocksMethod.Aes256Gcm);

        Assert.Throws<ArgumentException>(() =>
            new ShadowsocksStream(transport, ShadowsocksMethod.Aes128Gcm, key32, Salt(ShadowsocksMethod.Aes128Gcm, 1)));
        Assert.Throws<ArgumentException>(() =>
            new ShadowsocksStream(transport, ShadowsocksMethod.Aes256Gcm, key32, new byte[16]));
        Assert.Throws<ArgumentNullException>(() =>
            new ShadowsocksStream(null!, ShadowsocksMethod.Aes256Gcm, key32, Salt(ShadowsocksMethod.Aes256Gcm, 1)));
    }

    /// <summary>
    /// A write-only transport that counts its writes, so how many transport writes a
    /// <c>Write</c> turns into is observable.
    /// </summary>
    private sealed class CountingSink : Stream
    {
        private readonly List<byte> _written = [];

        public int WriteCount { get; private set; }
        public byte[] Written => [.. _written];

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            WriteCount++;
            _written.AddRange(buffer);
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <summary>
    /// A read-only transport that hands out a pre-recorded byte stream in slices of random
    /// length (1..maxSlice), so the reader sees salt, length blocks and payloads split anywhere.
    /// </summary>
    private sealed class RandomSliceStream(byte[] inbound, Random rng, int maxSlice) : Stream
    {
        private int _position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(Span<byte> buffer)
        {
            int remaining = inbound.Length - _position;
            if (remaining <= 0 || buffer.IsEmpty)
                return 0;

            int count = Math.Min(Math.Min(buffer.Length, rng.Next(1, maxSlice + 1)), remaining);
            inbound.AsSpan(_position, count).CopyTo(buffer);
            _position += count;
            return count;
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Read(buffer.Span));
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }
}
