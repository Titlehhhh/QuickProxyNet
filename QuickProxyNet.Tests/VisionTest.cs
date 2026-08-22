using System.Text;

namespace QuickProxyNet.Tests;

/// <summary>
/// The <c>xtls-rprx-vision</c> padding protocol, both directions.
/// </summary>
/// <remarks>
/// The failure this guards against is not a crash. A Vision stream read as plain VLESS almost
/// always yields a plausible first response — the padding header is 21 bytes and the payload
/// follows it — and corrupts everything after. So the assertions here are about the bytes past
/// the first frame as much as about the first one.
/// </remarks>
public class VisionTest
{
    private const string Uuid = "11223344-5566-7788-99aa-bbccddeeff00";

    private static readonly byte[] UuidBigEndian =
    [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
    ];

    private const byte PaddingContinue = 0x00;
    private const byte PaddingEnd = 0x01;

    /// <summary>Builds one padding frame, with the UUID prefix only when asked for.</summary>
    private static byte[] Frame(byte command, ReadOnlySpan<byte> content, int padding, bool withUuid)
    {
        var bytes = new List<byte>();
        if (withUuid)
            bytes.AddRange(UuidBigEndian);

        bytes.Add(command);
        bytes.Add((byte)(content.Length >> 8));
        bytes.Add((byte)content.Length);
        bytes.Add((byte)(padding >> 8));
        bytes.Add((byte)padding);
        bytes.AddRange(content.ToArray());
        bytes.AddRange(Enumerable.Repeat((byte)0xEE, padding)); // padding is skipped, not zero-checked
        return [.. bytes];
    }

    private static VisionStream Wrap(byte[] serverBytes, out MemoryStream sent)
    {
        var duplex = new DuplexStream(serverBytes);
        sent = duplex.Written;
        return new VisionStream(duplex, UuidBigEndian);
    }

    /// <summary>
    /// Drains the stream through either <c>ReadAsync</c> or the synchronous <c>Read(Span)</c>.
    /// The two paths are separate implementations inside <see cref="VisionStream"/>, so a
    /// divergence between them is caught only by running the same scenario through both.
    /// </summary>
    private static async Task<byte[]> ReadAllAsync(Stream stream, int chunk = 4096, bool sync = false)
    {
        var all = new MemoryStream();
        byte[] buffer = new byte[chunk];
        while (true)
        {
            int n = sync ? stream.Read(buffer.AsSpan()) : await stream.ReadAsync(buffer);
            if (n == 0)
                break;

            all.Write(buffer, 0, n);
        }

        return all.ToArray();
    }

    // === reading ===

    [Fact]
    public async Task Read_StripsASingleClosingFrame()
    {
        byte[] payload = Encoding.ASCII.GetBytes("HTTP/1.1 204 No Content\r\n\r\n");
        byte[] wire = [.. Frame(PaddingEnd, payload, padding: 64, withUuid: true), .. Encoding.ASCII.GetBytes("trailing")];

        await using VisionStream stream = Wrap(wire, out _);

        byte[] expected = [.. payload, .. Encoding.ASCII.GetBytes("trailing")];
        Assert.Equal(expected, await ReadAllAsync(stream));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Read_StripsSeveralFrames_AndOnlyTheFirstCarriesTheUuid(bool sync)
    {
        byte[] wire =
        [
            .. Frame(PaddingContinue, "one"u8, padding: 32, withUuid: true),
            .. Frame(PaddingContinue, "two"u8, padding: 0, withUuid: false),
            .. Frame(PaddingEnd, "three"u8, padding: 17, withUuid: false),
            .. "raw"u8.ToArray()
        ];

        await using VisionStream stream = Wrap(wire, out _);

        Assert.Equal("onetwothreeraw", Encoding.ASCII.GetString(await ReadAllAsync(stream, sync: sync)));
    }

    /// <summary>
    /// The frames are a byte stream, not packets: a header can straddle two reads and content
    /// can arrive one byte at a time. This is the case that a naive implementation passes in
    /// testing and fails against a real server.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Read_SurvivesFramesSplitAcrossEveryByteBoundary(bool sync)
    {
        byte[] wire =
        [
            .. Frame(PaddingContinue, "hello "u8, padding: 40, withUuid: true),
            .. Frame(PaddingEnd, "world"u8, padding: 3, withUuid: false),
            .. "!"u8.ToArray()
        ];

        var duplex = new DuplexStream(wire) { MaxRead = 1 };
        await using var stream = new VisionStream(duplex, UuidBigEndian);

        Assert.Equal("hello world!", Encoding.ASCII.GetString(await ReadAllAsync(stream, chunk: 3, sync: sync)));
    }

    [Fact]
    public async Task Read_PassesThroughWhenTheServerDoesNotFrame()
    {
        byte[] wire = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\n\r\nplain body, no vision here");

        await using VisionStream stream = Wrap(wire, out _);

        Assert.Equal(wire, await ReadAllAsync(stream));
    }

    /// <summary>A stream that ends before a first frame could exist is payload, not an error.</summary>
    [Fact]
    public async Task Read_ShortStreamIsPayload()
    {
        await using VisionStream stream = Wrap("hi"u8.ToArray(), out _);

        Assert.Equal("hi", Encoding.ASCII.GetString(await ReadAllAsync(stream)));
    }

    /// <summary>
    /// The <i>direct</i> command ends the framing just as <i>end</i> does. Live servers send it
    /// far more often, and a client that ignores it waits for a header that never comes — which
    /// is how this was found: against real nodes, not here.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Read_DirectCommandEndsTheFraming(bool sync)
    {
        const byte PaddingDirect = 0x02;
        byte[] wire =
        [
            .. Frame(PaddingDirect, "framed"u8, padding: 12, withUuid: true),
            .. Encoding.ASCII.GetBytes("everything after is raw")
        ];

        await using VisionStream stream = Wrap(wire, out _);

        Assert.Equal("framedeverything after is raw", Encoding.ASCII.GetString(await ReadAllAsync(stream, sync: sync)));
    }

    /// <summary>
    /// A server that simply closes on a frame boundary — no closing command — has ended the
    /// stream, not corrupted it. The distinction is the difference between a clean EOF and an
    /// exception on every completed download.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Read_CloseOnAFrameBoundaryIsACleanEnd(bool sync)
    {
        byte[] wire = Frame(PaddingContinue, "all there is"u8, padding: 8, withUuid: true);

        await using VisionStream stream = Wrap(wire, out _);

        Assert.Equal("all there is", Encoding.ASCII.GetString(await ReadAllAsync(stream, sync: sync)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Read_TruncatedFrameThrows(bool sync)
    {
        // A header promising 100 bytes of content, with 4 delivered.
        byte[] wire = Frame(PaddingEnd, "abcd"u8, padding: 0, withUuid: true);
        wire[UuidBigEndian.Length + 2] = 100;

        await using VisionStream stream = Wrap(wire, out _);

        await Assert.ThrowsAsync<EndOfStreamException>(async () => await ReadAllAsync(stream, sync: sync));
    }

    /// <summary>
    /// Padding-only frames are legal and Xray sends one or two. Sixty-five in a row is a peer
    /// keeping a read from returning, and the read must end in an error rather than never.
    /// </summary>
    [Fact]
    public async Task Read_PaddingOnlyFrameFlood_IsRefused()
    {
        var wire = new List<byte>();
        wire.AddRange(Frame(PaddingContinue, ReadOnlySpan<byte>.Empty, padding: 8, withUuid: true));
        for (int i = 0; i < 100; i++)
            wire.AddRange(Frame(PaddingContinue, ReadOnlySpan<byte>.Empty, padding: 8, withUuid: false));
        wire.AddRange(Frame(PaddingEnd, "late"u8, padding: 0, withUuid: false));

        await using VisionStream stream = Wrap([.. wire], out _);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () => await ReadAllAsync(stream));
        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
    }

    /// <summary>
    /// A server that is not framing and answers with fewer than 21 bytes — then waits for the
    /// client — must have those bytes delivered, not held until a header that is never coming.
    /// The first byte that is not the UUID already settles the question.
    /// </summary>
    [Fact]
    public async Task Read_ShortNonVisionAnswer_IsDeliveredWithoutWaitingForAFullHeader()
    {
        var source = new StallingStream("+OK\r\n"u8.ToArray());
        await using var stream = new VisionStream(source, UuidBigEndian);

        byte[] buffer = new byte[64];
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        int n = await stream.ReadAsync(buffer, timeout.Token);

        Assert.Equal("+OK\r\n", Encoding.ASCII.GetString(buffer, 0, n));
    }

    // === writing ===

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Write_PadsTheFirstWriteAndThenRunsRaw(bool sync)
    {
        await using VisionStream stream = Wrap([], out MemoryStream sent);

        if (sync)
        {
            stream.Write("GET / HTTP/1.1\r\n\r\n"u8);
            stream.Write("second"u8);
        }
        else
        {
            await stream.WriteAsync("GET / HTTP/1.1\r\n\r\n"u8.ToArray());
            await stream.WriteAsync("second"u8.ToArray());
        }

        byte[] written = sent.ToArray();
        Assert.Equal(UuidBigEndian, written[..16]);
        Assert.Equal(PaddingEnd, written[16]);

        int contentLength = (written[17] << 8) | written[18];
        int paddingLength = (written[19] << 8) | written[20];
        Assert.Equal(18, contentLength);
        Assert.Equal("GET / HTTP/1.1\r\n\r\n", Encoding.ASCII.GetString(written, 21, contentLength));

        // Everything after the frame is the second write, unwrapped.
        int frameEnd = 21 + contentLength + paddingLength;
        Assert.Equal("second", Encoding.ASCII.GetString(written, frameEnd, written.Length - frameEnd));
    }

    /// <summary>
    /// Xray pads a short packet out past 900 bytes. Matching that matters: the padding exists to
    /// make the first records an uninformative length, and a distinctly-sized one is worse than
    /// none at all.
    /// </summary>
    [Fact]
    public async Task Write_PadsShortPacketsPastNineHundredBytes()
    {
        await using VisionStream stream = Wrap([], out MemoryStream sent);

        await stream.WriteAsync("tiny"u8.ToArray());

        byte[] written = sent.ToArray();
        int contentLength = (written[17] << 8) | written[18];
        int paddingLength = (written[19] << 8) | written[20];
        Assert.Equal(4, contentLength);
        Assert.InRange(contentLength + paddingLength, 900, 1400);
    }

    [Fact]
    public async Task Write_OversizedFirstWriteGoesOutRaw()
    {
        byte[] big = new byte[9000];
        Array.Fill(big, (byte)0x5A);

        await using VisionStream stream = Wrap([], out MemoryStream sent);
        await stream.WriteAsync(big);

        Assert.Equal(big, sent.ToArray());
    }

    // === the request header that turns Vision on ===

    [Fact]
    public void BuildRequest_CarriesFlowInTheAddons()
    {
        Span<byte> buf = stackalloc byte[512];
        int n = VlessHelper.BuildRequest(buf, Uuid, "example.com", 443, VisionStream.FlowName);

        byte[] wire = buf[..n].ToArray();
        Assert.Equal(0x00, wire[0]);
        Assert.Equal(UuidBigEndian, wire[1..17]);
        Assert.Equal(2 + VisionStream.FlowName.Length, wire[17]); // addons length
        Assert.Equal(0x0A, wire[18]);                             // Addons.Flow, wire type 2
        Assert.Equal(VisionStream.FlowName.Length, wire[19]);
        Assert.Equal(VisionStream.FlowName, Encoding.ASCII.GetString(wire, 20, VisionStream.FlowName.Length));

        int afterAddons = 20 + VisionStream.FlowName.Length;
        Assert.Equal(0x01, wire[afterAddons]);                    // command TCP
        Assert.Equal(443, (wire[afterAddons + 1] << 8) | wire[afterAddons + 2]);
        Assert.Equal(0x02, wire[afterAddons + 3]);                // domain
    }

    [Fact]
    public void BuildRequest_WithoutFlow_IsUnchanged()
    {
        Span<byte> withoutFlow = stackalloc byte[512];
        int n = VlessHelper.BuildRequest(withoutFlow, Uuid, "example.com", 443);

        Assert.Equal(0x00, withoutFlow[17]); // addons length stays zero
        Assert.Equal(0x01, withoutFlow[18]); // command TCP follows immediately
        Assert.Equal(1 + 16 + 1 + 1 + 2 + 2 + "example.com".Length, n);
    }

    [Fact]
    public void IsVision_MatchesOnlyTheImplementedFlow()
    {
        Assert.True(VlessHelper.IsVision("xtls-rprx-vision"));
        Assert.False(VlessHelper.IsVision("xtls-rprx-direct"));
        Assert.False(VlessHelper.IsVision("XTLS-RPRX-VISION"));
        Assert.False(VlessHelper.IsVision(null));
        Assert.False(VlessHelper.IsVision(""));
    }

    /// <summary>Hands out one chunk, then blocks like a peer that is waiting for its turn.</summary>
    private sealed class StallingStream(byte[] first) : Stream
    {
        private bool _served;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!_served)
            {
                _served = true;
                int n = Math.Min(buffer.Length, first.Length);
                first.AsSpan(0, n).CopyTo(buffer.Span);
                return n;
            }

            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Write(byte[] buffer, int offset, int count) { }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    /// <summary>A stream that reads from a fixed script and records what was written.</summary>
    private sealed class DuplexStream(byte[] serverBytes) : Stream
    {
        private int _position;

        public MemoryStream Written { get; } = new();

        /// <summary>Caps how much one read returns, to simulate a stream that dribbles.</summary>
        public int MaxRead { get; init; } = int.MaxValue;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => serverBytes.Length;

        public override long Position
        {
            get => _position;
            set => throw new NotSupportedException();
        }

        public override int Read(Span<byte> buffer)
        {
            int n = Math.Min(Math.Min(buffer.Length, MaxRead), serverBytes.Length - _position);
            serverBytes.AsSpan(_position, n).CopyTo(buffer);
            _position += n;
            return n;
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => ValueTask.FromResult(Read(buffer.Span));

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => Task.FromResult(Read(buffer.AsSpan(offset, count)));

        public override void Write(ReadOnlySpan<byte> buffer) => Written.Write(buffer);

        public override void Write(byte[] buffer, int offset, int count) => Written.Write(buffer, offset, count);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Written.Write(buffer.Span);
            return ValueTask.CompletedTask;
        }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
