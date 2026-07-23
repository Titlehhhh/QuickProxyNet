using System.Buffers.Binary;
using System.Security.Cryptography;
using QuickProxyNet.Tests.Helpers;

// CA2022 ("avoid inexact reads") warns whenever a single ReadAsync is expected to fill a
// buffer. Chunk-at-a-time delivery is exactly what these tests assert, so the analyzer is
// off for this file.
#pragma warning disable CA2022

namespace QuickProxyNet.Tests;

/// <summary>
/// Tests for the VMessAEAD (alterId = 0) server response header (<see cref="VmessResponse"/>)
/// and the encrypted body stream (<see cref="VmessStream"/>).
///
/// Every wire vector below is GROUND TRUTH produced by an independent Python
/// reimplementation (scratchpad/vmess_body_truth.py) written from docs/vmess-aead-body.md
/// alone — stdlib hashlib/struct, a hand-rolled ipad/opad nested KDF, and AES-GCM /
/// ChaCha20-Poly1305 from `cryptography`. That script first reproduces public digests and
/// every response-header KDF / body-key vector already committed in VmessCryptoTest.cs
/// before a single new byte is trusted.
///
/// All inputs are synthetic counting byte patterns; the body key and IV are the same ones
/// VmessRequestTest.cs puts in the request header, so the two suites describe one session.
/// </summary>
public class VmessBodyTest
{
    // ---- synthetic session (must match scratchpad/vmess_body_truth.py) ----
    private static readonly byte[] RequestBodyKey = Hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"); // b0..bf
    private static readonly byte[] RequestBodyIv = Hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");  // a0..af
    private const byte RespV = 0x2A;

    // ---- pinned §1.1 / §3.2 derivations ----
    private const string ExpectedResponseBodyKey = "9f52527783ea1185acd5d4dcf1bf91b7";
    private const string ExpectedResponseBodyIv = "503563c1bda45327ff4617750a06bd81";
    private const string ExpectedLengthKey = "9aa6c3a953070fb2b824d497eff752eb";
    private const string ExpectedLengthIv = "e78e477b1580b507a7b362d4";
    private const string ExpectedHeaderKey = "121c1a9b66ac3e594b88e0dc0b18cf4e";
    private const string ExpectedHeaderIv = "97b677a44b45c1ebaa0b9dca";

    // ---- pinned §3.3 response-header wire blobs ----
    // plaintext 2a 00 00 00  (respV, option 0, command 0, commandLength 0)
    private const string ResponseHeaderSimple =
        "81ca9ac9e3abe6c98c139ad323b26980eff9" +
        "35010f1736251faac223a9f0b6850515d7551c49";

    // plaintext 2a 11 01 03 aa bb cc  (option 0x11, command 1, 3 bytes of command data)
    private const string ResponseHeaderWithCommand =
        "81c9eb8cb14aa1f067216223a98cf6de6b5c" +
        "35100e1490b0751dd3edb3d77003356deb9dba3b262609";

    // ---- pinned §2 body chunks: "hello", "A", then the empty terminating chunk ----
    private const string ReqAesChunk0 = "001544389a0d0c1a7cfbb71cffad86675dd476786bf27e";
    private const string ReqAesChunk1 = "001175176c3bb4505f393ef9a69e4edfb3658c";
    private const string ReqAesChunk2 = "00108395338e49af5292e4781b6bd1bb1740";
    private const string ReqAesStream = ReqAesChunk0 + ReqAesChunk1 + ReqAesChunk2;

    private const string RespAesChunk0 = "001552e3196f715e243c00a891bdf7d6e27f0ea77bdc5c";
    private const string RespAesChunk1 = "001103bd1f0c159ce095a258433d6abd36b5ae";
    private const string RespAesChunk2 = "00109bd03fbc3f9121279559c23d393cc81f";
    private const string RespAesStream = RespAesChunk0 + RespAesChunk1 + RespAesChunk2;

    private const string ReqChaChaStream =
        "0015c3594c59801a4515b6568b2f7d20e718896061fa0c" +
        "00116b1fb18d3171052494b63e7764f2b94336" +
        "0010714efaf791b66f10a481aaa6ef614e6c";

    private const string RespChaChaStream =
        "0015414af98c7ab728bb713e78cd2d85532c776286c679" +
        "0011a2a7190cc1e6d6a7102002dde97f92bbb6" +
        "0010dc6d73c188506318fe0317271056986a";

    private const string ExpectedChaChaRequestKey =
        "790c29e849c35d78178bd38cee4cb5e38c9fa2ef9aa23a1cfc546c546f01046c";

    private static byte[] Hex(string h) => Convert.FromHexString(h);
    private static byte[] ResponseBodyKey => Hex(ExpectedResponseBodyKey);
    private static byte[] ResponseBodyIv => Hex(ExpectedResponseBodyIv);

    private static VmessStream ClientStream(
        DuplexTestStream transport, VmessSecurity security = VmessSecurity.Aes128Gcm)
        => new(transport, RequestBodyKey, RequestBodyIv, ResponseBodyKey, ResponseBodyIv,
            security, leaveInnerOpen: true);

    // Independent re-implementation of §1.4 + §2.1, used only to build the oversized
    // fixtures the pinned vectors do not cover.
    private static byte[] SealChunk(byte[] key, byte[] iv, ushort counter, byte[] plaintext)
    {
        byte[] nonce = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(nonce, counter);
        iv.AsSpan(2, 10).CopyTo(nonce.AsSpan(2));

        byte[] wire = new byte[2 + plaintext.Length + 16];
        BinaryPrimitives.WriteUInt16BigEndian(wire, (ushort)(plaintext.Length + 16));
        using var gcm = new AesGcm(key, 16);
        gcm.Encrypt(nonce, plaintext, wire.AsSpan(2, plaintext.Length), wire.AsSpan(2 + plaintext.Length, 16));
        return wire;
    }

    private static byte[] Concat(byte[] first, byte[] second)
    {
        byte[] result = new byte[first.Length + second.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);
        return result;
    }

    // ========================= test-helper anchor =========================

    [Fact]
    public void SealChunkHelper_ReproducesThePinnedChunks()
    {
        // The local §1.4/§2.1 re-implementation is only trustworthy if it reproduces the
        // Python-pinned chunks, so anchor it before using it to build fixtures.
        Assert.Equal(ReqAesChunk0,
            Convert.ToHexStringLower(SealChunk(RequestBodyKey, RequestBodyIv, 0, "hello"u8.ToArray())));
        Assert.Equal(ReqAesChunk1,
            Convert.ToHexStringLower(SealChunk(RequestBodyKey, RequestBodyIv, 1, [0x41])));
        Assert.Equal(ReqAesChunk2,
            Convert.ToHexStringLower(SealChunk(RequestBodyKey, RequestBodyIv, 2, [])));
        Assert.Equal(RespAesChunk0,
            Convert.ToHexStringLower(SealChunk(ResponseBodyKey, ResponseBodyIv, 0, "hello"u8.ToArray())));
        Assert.Equal(RespAesChunk2,
            Convert.ToHexStringLower(SealChunk(ResponseBodyKey, ResponseBodyIv, 2, [])));
    }

    // ========================= §1.1 response key/IV =========================

    [Fact]
    public void DeriveBodyKeys_MatchesGroundTruth()
    {
        Span<byte> key = stackalloc byte[16];
        Span<byte> iv = stackalloc byte[16];
        VmessResponse.DeriveBodyKeys(RequestBodyKey, RequestBodyIv, key, iv);

        Assert.Equal(ExpectedResponseBodyKey, Convert.ToHexStringLower(key));
        Assert.Equal(ExpectedResponseBodyIv, Convert.ToHexStringLower(iv));
    }

    [Fact]
    public void DeriveBodyKeys_IsSha256Truncated()
    {
        // Independent re-computation of §1.1 straight from SHA-256.
        Assert.Equal(
            ExpectedResponseBodyKey,
            Convert.ToHexStringLower(SHA256.HashData(RequestBodyKey).AsSpan(0, 16)));
        Assert.Equal(
            ExpectedResponseBodyIv,
            Convert.ToHexStringLower(SHA256.HashData(RequestBodyIv).AsSpan(0, 16)));
    }

    [Fact]
    public void DeriveBodyKeys_WrongInputSize_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> key = stackalloc byte[16];
            Span<byte> iv = stackalloc byte[16];
            VmessResponse.DeriveBodyKeys(new byte[15], RequestBodyIv, key, iv);
        });

        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> key = stackalloc byte[16];
            Span<byte> iv = stackalloc byte[16];
            VmessResponse.DeriveBodyKeys(RequestBodyKey, new byte[17], key, iv);
        });
    }

    // ========================= §3.2 response-header KDF =========================

    [Fact]
    public void DeriveHeaderKeys_MatchesGroundTruth()
    {
        Span<byte> lengthKey = stackalloc byte[16];
        Span<byte> lengthIv = stackalloc byte[12];
        Span<byte> headerKey = stackalloc byte[16];
        Span<byte> headerIv = stackalloc byte[12];

        VmessResponse.DeriveHeaderKeys(
            ResponseBodyKey, ResponseBodyIv, lengthKey, lengthIv, headerKey, headerIv);

        Assert.Equal(ExpectedLengthKey, Convert.ToHexStringLower(lengthKey));
        Assert.Equal(ExpectedLengthIv, Convert.ToHexStringLower(lengthIv));
        Assert.Equal(ExpectedHeaderKey, Convert.ToHexStringLower(headerKey));
        Assert.Equal(ExpectedHeaderIv, Convert.ToHexStringLower(headerIv));
    }

    [Fact]
    public void DeriveHeaderKeys_KeysComeFromTheKey_IvsFromTheIv()
    {
        // Re-derive each value with the single-path KDF directly: both *keys* must be
        // functions of responseBodyKey only, both *IVs* of responseBodyIV only.
        Span<byte> scratch = stackalloc byte[16];
        VmessKdf.Kdf16(ResponseBodyKey, "AEAD Resp Header Len Key"u8, scratch);
        Assert.Equal(ExpectedLengthKey, Convert.ToHexStringLower(scratch));

        VmessKdf.Kdf16(ResponseBodyKey, "AEAD Resp Header Key"u8, scratch);
        Assert.Equal(ExpectedHeaderKey, Convert.ToHexStringLower(scratch));

        Span<byte> nonce = stackalloc byte[12];
        VmessKdf.Kdf12(ResponseBodyIv, "AEAD Resp Header Len IV"u8, nonce);
        Assert.Equal(ExpectedLengthIv, Convert.ToHexStringLower(nonce));

        VmessKdf.Kdf12(ResponseBodyIv, "AEAD Resp Header IV"u8, nonce);
        Assert.Equal(ExpectedHeaderIv, Convert.ToHexStringLower(nonce));

        // Swapping the two inputs must NOT reproduce the pinned values.
        VmessKdf.Kdf16(ResponseBodyIv, "AEAD Resp Header Key"u8, scratch);
        Assert.NotEqual(ExpectedHeaderKey, Convert.ToHexStringLower(scratch));
    }

    [Fact]
    public void DeriveHeaderKeys_WrongInputSize_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
        {
            Span<byte> lengthKey = stackalloc byte[16];
            Span<byte> lengthIv = stackalloc byte[12];
            Span<byte> headerKey = stackalloc byte[16];
            Span<byte> headerIv = stackalloc byte[12];
            VmessResponse.DeriveHeaderKeys(new byte[15], ResponseBodyIv, lengthKey, lengthIv, headerKey, headerIv);
        });
    }

    // ========================= §3.3/§3.4 response header =========================

    [Fact]
    public async Task ReadResponseHeader_HappyPath_MatchesGroundTruth()
    {
        var transport = new DuplexTestStream(Hex(ResponseHeaderSimple + RespAesStream));

        var header = await VmessResponse.ReadAsync(
            transport, ResponseBodyKey, ResponseBodyIv, RespV, CancellationToken.None);

        Assert.Equal(RespV, header.ResponseVerifier);
        Assert.Equal(0x00, header.Option);
        Assert.Equal(0x00, header.Command);
        Assert.Equal(0x00, header.CommandLength);

        // Exactly 18 + 4 + 16 = 38 bytes consumed; the body chunks are left untouched.
        Assert.Equal(RespAesStream, Convert.ToHexStringLower(transport.Unread));
    }

    [Fact]
    public async Task ReadResponseHeader_WithCommand_ParsesAndSkipsCommandData()
    {
        var transport = new DuplexTestStream(Hex(ResponseHeaderWithCommand));

        var header = await VmessResponse.ReadAsync(
            transport, ResponseBodyKey, ResponseBodyIv, RespV, CancellationToken.None);

        Assert.Equal(RespV, header.ResponseVerifier);
        Assert.Equal(0x11, header.Option);
        Assert.Equal(0x01, header.Command);
        Assert.Equal(0x03, header.CommandLength);

        // The command data lives inside the sealed header, so nothing is left over.
        Assert.Empty(transport.Unread);
    }

    [Fact]
    public async Task ReadResponseHeader_ResponseVerifierMismatch_IsRejected()
    {
        var transport = new DuplexTestStream(Hex(ResponseHeaderSimple));

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () =>
            await VmessResponse.ReadAsync(
                transport, ResponseBodyKey, ResponseBodyIv, 0x2B, CancellationToken.None));

        Assert.Equal(ProxyErrorCode.AuthFailed, ex.ErrorCode);
        Assert.Contains("0x2B", ex.Message);
        Assert.Contains("0x2A", ex.Message);
    }

    [Fact]
    public async Task ReadResponseHeader_TruncatedLengthPrefix_IsAnErrorNotEof()
    {
        // 17 of the 18 length bytes: truncation, never a clean end of stream.
        var transport = new DuplexTestStream(Hex(ResponseHeaderSimple)[..17]);

        await Assert.ThrowsAsync<EndOfStreamException>(async () =>
            await VmessResponse.ReadAsync(
                transport, ResponseBodyKey, ResponseBodyIv, RespV, CancellationToken.None));
    }

    [Fact]
    public async Task ReadResponseHeader_EmptyStream_IsAnErrorNotEof()
    {
        var transport = new DuplexTestStream([]);

        await Assert.ThrowsAsync<EndOfStreamException>(async () =>
            await VmessResponse.ReadAsync(
                transport, ResponseBodyKey, ResponseBodyIv, RespV, CancellationToken.None));
    }

    [Fact]
    public async Task ReadResponseHeader_TruncatedSealedHeader_IsAnErrorNotEof()
    {
        // Full 18-byte length block, then only 19 of the 20 sealed header bytes.
        var transport = new DuplexTestStream(Hex(ResponseHeaderSimple)[..^1]);

        await Assert.ThrowsAsync<EndOfStreamException>(async () =>
            await VmessResponse.ReadAsync(
                transport, ResponseBodyKey, ResponseBodyIv, RespV, CancellationToken.None));
    }

    [Fact]
    public async Task ReadResponseHeader_TamperedLengthBlock_FailsAuthentication()
    {
        byte[] wire = Hex(ResponseHeaderSimple);
        wire[0] ^= 0xFF;
        var transport = new DuplexTestStream(wire);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () =>
            await VmessResponse.ReadAsync(
                transport, ResponseBodyKey, ResponseBodyIv, RespV, CancellationToken.None));

        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
        Assert.IsType<AuthenticationTagMismatchException>(ex.InnerException);
    }

    [Fact]
    public async Task ReadResponseHeader_TamperedHeader_FailsAuthentication()
    {
        byte[] wire = Hex(ResponseHeaderSimple);
        wire[^1] ^= 0xFF;
        var transport = new DuplexTestStream(wire);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () =>
            await VmessResponse.ReadAsync(
                transport, ResponseBodyKey, ResponseBodyIv, RespV, CancellationToken.None));

        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
    }

    [Fact]
    public async Task ReadResponseHeader_WrongKeySize_Throws()
    {
        var transport = new DuplexTestStream(Hex(ResponseHeaderSimple));

        await Assert.ThrowsAsync<ArgumentException>(async () =>
            await VmessResponse.ReadAsync(
                transport, new byte[15], ResponseBodyIv, RespV, CancellationToken.None));
    }

    [Fact]
    public async Task ReadResponseHeader_DrippingTransport_ReadsExactly()
    {
        // A transport that hands out one byte at a time must still reassemble the header.
        var transport = new DuplexTestStream(Hex(ResponseHeaderSimple + RespAesStream), maxReadSize: 1);

        var header = await VmessResponse.ReadAsync(
            transport, ResponseBodyKey, ResponseBodyIv, RespV, CancellationToken.None);

        Assert.Equal(RespV, header.ResponseVerifier);
        Assert.Equal(RespAesStream, Convert.ToHexStringLower(transport.Unread));
    }

    // ========================= §2 body: write path =========================

    [Fact]
    public async Task Write_ProducesThePinnedWireBytes()
    {
        var transport = new DuplexTestStream([]);
        var stream = ClientStream(transport);

        await stream.WriteAsync("hello"u8.ToArray());
        Assert.Equal(ReqAesChunk0, Convert.ToHexStringLower(transport.Written));

        await stream.WriteAsync(new byte[] { 0x41 });
        Assert.Equal(ReqAesChunk0 + ReqAesChunk1, Convert.ToHexStringLower(transport.Written));

        await stream.CompleteWriteAsync();
        Assert.Equal(ReqAesStream, Convert.ToHexStringLower(transport.Written));
    }

    [Fact]
    public async Task Write_LengthFieldIsTheSealedSize_NotThePlaintextSize()
    {
        var transport = new DuplexTestStream([]);
        var stream = ClientStream(transport);

        await stream.WriteAsync("hello"u8.ToArray());

        byte[] wire = transport.Written;
        Assert.Equal(21, BinaryPrimitives.ReadUInt16BigEndian(wire)); // 5 + 16, not 5
        Assert.Equal(23, wire.Length);                                // 2 + 21
    }

    [Fact]
    public async Task Write_TerminatorIsAnAuthenticatedEmptyChunk()
    {
        var transport = new DuplexTestStream([]);
        var stream = ClientStream(transport);

        await stream.CompleteWriteAsync();

        byte[] wire = transport.Written;
        Assert.Equal(18, wire.Length);
        Assert.Equal(0x00, wire[0]);
        Assert.Equal(0x10, wire[1]); // length == Overhead == 16
        Assert.True(stream.IsWriteCompleted);
    }

    [Fact]
    public async Task Write_TerminatorIsIdempotent()
    {
        var transport = new DuplexTestStream([]);
        var stream = ClientStream(transport);

        await stream.CompleteWriteAsync();
        await stream.CompleteWriteAsync();
        await stream.DisposeAsync();
        await stream.DisposeAsync();

        Assert.Equal(18, transport.Written.Length);
    }

    [Fact]
    public async Task Dispose_WritesTheTerminatingChunkExactlyOnce()
    {
        var transport = new DuplexTestStream([]);
        var stream = ClientStream(transport);

        await stream.WriteAsync("hello"u8.ToArray());
        await stream.WriteAsync(new byte[] { 0x41 });
        await stream.DisposeAsync();

        Assert.Equal(ReqAesStream, Convert.ToHexStringLower(transport.Written));
    }

    [Fact]
    public async Task Dispose_DisposesTheInnerStreamUnlessAskedNotTo()
    {
        var owned = new DuplexTestStream([]);
        await new VmessStream(owned, RequestBodyKey, RequestBodyIv, ResponseBodyKey, ResponseBodyIv,
            VmessSecurity.Aes128Gcm).DisposeAsync();
        Assert.Equal(1, owned.DisposeCount);

        var borrowed = new DuplexTestStream([]);
        await ClientStream(borrowed).DisposeAsync();
        Assert.Equal(0, borrowed.DisposeCount);
    }

    [Fact]
    public async Task Write_AfterCompletion_Throws()
    {
        var transport = new DuplexTestStream([]);
        var stream = ClientStream(transport);
        await stream.CompleteWriteAsync();

        Assert.False(stream.CanWrite);
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await stream.WriteAsync("x"u8.ToArray()));
    }

    [Fact]
    public async Task Write_EmptyBuffer_EmitsNothing()
    {
        var transport = new DuplexTestStream([]);
        var stream = ClientStream(transport);

        await stream.WriteAsync(ReadOnlyMemory<byte>.Empty);

        // An empty write must NOT be confused with the terminating chunk.
        Assert.Empty(transport.Written);
        Assert.Equal(0, stream.WriteChunkCounter);
    }

    [Fact]
    public async Task Write_LargeBuffer_SplitsAtTheSendChunkBound()
    {
        var transport = new DuplexTestStream([]);
        var stream = ClientStream(transport);

        byte[] payload = new byte[20000];
        for (int i = 0; i < payload.Length; i++)
            payload[i] = (byte)i;

        await stream.WriteAsync(payload);

        byte[] wire = transport.Written;
        int offset = 0;
        foreach (int plaintextLength in new[] { 8174, 8174, 20000 - (2 * 8174) })
        {
            Assert.Equal(plaintextLength + 16, BinaryPrimitives.ReadUInt16BigEndian(wire.AsSpan(offset)));
            offset += 2 + plaintextLength + 16;
        }

        Assert.Equal(wire.Length, offset);
        Assert.Equal(3, stream.WriteChunkCounter);
        Assert.Equal(8174, VmessStream.MaxSendPlaintextSize);
    }

    [Fact]
    public void Write_SyncOverloadDelegatesToTheAsyncPath()
    {
        var transport = new DuplexTestStream([]);
        var stream = ClientStream(transport);

        stream.Write("hello"u8);
        stream.Write([0x41], 0, 1);

        Assert.Equal(ReqAesChunk0 + ReqAesChunk1, Convert.ToHexStringLower(transport.Written));
    }

    // ========================= §2 body: read path =========================

    [Fact]
    public async Task Read_RoundTripsThePinnedWireBytes()
    {
        var transport = new DuplexTestStream(Hex(RespAesStream));
        var stream = ClientStream(transport);

        byte[] buffer = new byte[64];

        int read = await stream.ReadAsync(buffer);
        Assert.Equal("hello"u8.ToArray(), buffer[..read]);

        read = await stream.ReadAsync(buffer);
        Assert.Equal(new byte[] { 0x41 }, buffer[..read]);

        Assert.Equal(0, await stream.ReadAsync(buffer));
        Assert.True(stream.IsReadCompleted);

        // Subsequent reads keep reporting a clean end of stream.
        Assert.Equal(0, await stream.ReadAsync(buffer));
    }

    [Fact]
    public async Task Read_BufferSmallerThanTheChunk_BuffersTheLeftover()
    {
        var transport = new DuplexTestStream(Hex(RespAesStream));
        var stream = ClientStream(transport);

        byte[] two = new byte[2];
        var assembled = new List<byte>();

        for (int i = 0; i < 3; i++)
        {
            int read = await stream.ReadAsync(two);
            assembled.AddRange(two[..read]);
        }

        // "hello" is 5 bytes: 2 + 2 + 1 — the third read must stop at the chunk boundary
        // instead of merging the next chunk in, and only one chunk may have been opened.
        Assert.Equal("hello"u8.ToArray(), assembled);
        Assert.Equal(1, stream.ReadChunkCounter);

        int last = await stream.ReadAsync(two);
        Assert.Equal(new byte[] { 0x41 }, two[..last]);
        Assert.Equal(0, await stream.ReadAsync(two));
    }

    [Fact]
    public async Task Read_DrippingTransport_ReassemblesChunks()
    {
        var transport = new DuplexTestStream(Hex(RespAesStream), maxReadSize: 1);
        var stream = ClientStream(transport);

        byte[] buffer = new byte[64];
        int read = await stream.ReadAsync(buffer);

        Assert.Equal("hello"u8.ToArray(), buffer[..read]);
    }

    [Fact]
    public async Task Read_EmptyChunkIsTheOnlyCleanEof()
    {
        // A stream whose very first chunk is the terminator (counter 0).
        var transport = new DuplexTestStream(SealChunk(ResponseBodyKey, ResponseBodyIv, 0, []));
        var stream = ClientStream(transport);

        Assert.Equal(0, await stream.ReadAsync(new byte[16]));
        Assert.True(stream.IsReadCompleted);
        Assert.Equal(1, stream.ReadChunkCounter); // the empty chunk was opened and verified
    }

    [Fact]
    public async Task Read_BadTag_IsAHardErrorNotEof()
    {
        byte[] wire = Hex(RespAesChunk0);
        wire[^1] ^= 0xFF;
        var transport = new DuplexTestStream(wire);
        var stream = ClientStream(transport);

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(async () =>
            await stream.ReadAsync(new byte[64]));
    }

    [Fact]
    public async Task Read_TamperedTerminator_IsAHardErrorNotEof()
    {
        byte[] wire = SealChunk(ResponseBodyKey, ResponseBodyIv, 0, []);
        wire[^1] ^= 0xFF;
        var transport = new DuplexTestStream(wire);
        var stream = ClientStream(transport);

        // The empty chunk is authenticated: a broken tag must not be reported as EOF.
        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(async () =>
            await stream.ReadAsync(new byte[64]));
        Assert.False(stream.IsReadCompleted);
    }

    [Fact]
    public async Task Read_ChunksOutOfOrder_FailTheNonceCheck()
    {
        // The chunk sealed with counter 1 cannot be opened as if it were chunk 0.
        var transport = new DuplexTestStream(Hex(RespAesChunk1));
        var stream = ClientStream(transport);

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(async () =>
            await stream.ReadAsync(new byte[64]));
    }

    [Fact]
    public async Task Read_TruncatedLengthPrefix_IsAnErrorNotEof()
    {
        var transport = new DuplexTestStream([0x00]);
        var stream = ClientStream(transport);

        await Assert.ThrowsAsync<EndOfStreamException>(async () =>
            await stream.ReadAsync(new byte[64]));
    }

    [Fact]
    public async Task Read_TruncatedChunkBody_IsAnErrorNotEof()
    {
        var transport = new DuplexTestStream(Hex(RespAesChunk0)[..^1]);
        var stream = ClientStream(transport);

        await Assert.ThrowsAsync<EndOfStreamException>(async () =>
            await stream.ReadAsync(new byte[64]));
    }

    [Fact]
    public async Task Read_TransportClosedWithoutTerminator_IsAnErrorNotEof()
    {
        // A complete data chunk, then a FIN with no terminating empty chunk.
        var transport = new DuplexTestStream(Hex(RespAesChunk0));
        var stream = ClientStream(transport);

        byte[] buffer = new byte[64];
        Assert.Equal(5, await stream.ReadAsync(buffer));
        await Assert.ThrowsAsync<EndOfStreamException>(async () =>
            await stream.ReadAsync(buffer));
    }

    [Fact]
    public async Task Read_LengthBelowTheTagSize_IsRejected()
    {
        byte[] wire = new byte[17];
        wire[1] = 0x0F; // a sealed chunk shorter than the 16-byte tag is impossible
        var transport = new DuplexTestStream(wire);
        var stream = ClientStream(transport);

        var ex = await Assert.ThrowsAsync<ProxyProtocolException>(async () =>
            await stream.ReadAsync(new byte[64]));

        Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
    }

    [Fact]
    public async Task Read_AcceptsChunksLargerThan16384_UpToTheUint16Cap()
    {
        // 65519 is the wire-format maximum plaintext (65535 - 16); "16384" is not a
        // v2ray/Xray constant and must not be used as a receive limit.
        byte[] payload = new byte[VmessStream.MaxReceivePlaintextSize];
        for (int i = 0; i < payload.Length; i++)
            payload[i] = (byte)(i * 7);

        byte[] wire = Concat(
            SealChunk(ResponseBodyKey, ResponseBodyIv, 0, payload),
            SealChunk(ResponseBodyKey, ResponseBodyIv, 1, []));

        var transport = new DuplexTestStream(wire);
        var stream = ClientStream(transport);

        byte[] received = new byte[payload.Length];
        int offset = 0;
        while (offset < received.Length)
        {
            int read = await stream.ReadAsync(received.AsMemory(offset));
            Assert.True(read > 0);
            offset += read;
        }

        Assert.Equal(payload, received);
        Assert.Equal(65519, VmessStream.MaxReceivePlaintextSize);
        Assert.Equal(0, await stream.ReadAsync(received));
    }

    [Fact]
    public void Read_SyncOverloadDelegatesToTheAsyncPath()
    {
        var transport = new DuplexTestStream(Hex(RespAesStream));
        var stream = ClientStream(transport);

        Span<byte> buffer = stackalloc byte[64];
        int read = stream.Read(buffer);
        Assert.Equal("hello"u8.ToArray(), buffer[..read].ToArray());

        byte[] array = new byte[64];
        read = stream.Read(array, 0, array.Length);
        Assert.Equal(new byte[] { 0x41 }, array[..read]);
        Assert.Equal(0, stream.Read(array, 0, array.Length));
    }

    // ========================= §1.4 nonce evolution =========================

    [Fact]
    public async Task ChunkNonce_CounterIncrements_AndTheIvTailStaysConstant()
    {
        var transport = new DuplexTestStream([]);
        var stream = ClientStream(transport);

        Assert.Equal(0, stream.WriteChunkCounter);
        await stream.WriteAsync("hello"u8.ToArray());
        Assert.Equal(1, stream.WriteChunkCounter);
        await stream.WriteAsync(new byte[] { 0x41 });
        Assert.Equal(2, stream.WriteChunkCounter);
        await stream.CompleteWriteAsync();
        Assert.Equal(3, stream.WriteChunkCounter);

        // Re-open every chunk with an independently constructed nonce:
        // nonce[0:2] = uint16 BE counter, nonce[2:12] = requestBodyIV[2:12].
        byte[] wire = transport.Written;
        byte[][] expectedPlaintexts = ["hello"u8.ToArray(), [0x41], []];

        int offset = 0;
        using var gcm = new AesGcm(RequestBodyKey, 16);

        for (ushort counter = 0; counter < expectedPlaintexts.Length; counter++)
        {
            int sealedLength = BinaryPrimitives.ReadUInt16BigEndian(wire.AsSpan(offset));
            int plaintextLength = sealedLength - 16;

            byte[] nonce = new byte[12];
            BinaryPrimitives.WriteUInt16BigEndian(nonce, counter);
            RequestBodyIv.AsSpan(2, 10).CopyTo(nonce.AsSpan(2));

            // Only the first two bytes ever change; the tail is the body IV verbatim.
            Assert.Equal(RequestBodyIv[2..12], nonce[2..12]);
            Assert.Equal(counter, BinaryPrimitives.ReadUInt16BigEndian(nonce));

            byte[] plaintext = new byte[plaintextLength];
            byte[] ciphertext = wire[(offset + 2)..(offset + 2 + plaintextLength)];
            byte[] tag = wire[(offset + 2 + plaintextLength)..(offset + 2 + sealedLength)];
            gcm.Decrypt(nonce, ciphertext, tag, plaintext);
            Assert.Equal(expectedPlaintexts[counter], plaintext);

            // A stale counter must not authenticate.
            if (counter > 0)
            {
                byte[] stale = (byte[])nonce.Clone();
                BinaryPrimitives.WriteUInt16BigEndian(stale, (ushort)(counter - 1));
                Assert.Throws<AuthenticationTagMismatchException>(() =>
                    gcm.Decrypt(stale, ciphertext, tag, new byte[plaintextLength]));
            }

            offset += 2 + sealedLength;
        }

        Assert.Equal(wire.Length, offset);
    }

    // ========================= ciphers & framing options =========================

    [Fact]
    public async Task ChaCha20_WriteAndRead_MatchThePinnedWireBytes()
    {
        if (!ChaCha20Poly1305.IsSupported)
            return; // gated exactly like the implementation

        Span<byte> expanded = stackalloc byte[32];
        VmessBodyKeys.ExpandChaCha20Key(RequestBodyKey, expanded);
        Assert.Equal(ExpectedChaChaRequestKey, Convert.ToHexStringLower(expanded));

        var transport = new DuplexTestStream(Hex(RespChaChaStream));
        var stream = ClientStream(transport, VmessSecurity.ChaCha20Poly1305);

        await stream.WriteAsync("hello"u8.ToArray());
        await stream.WriteAsync(new byte[] { 0x41 });
        await stream.CompleteWriteAsync();
        Assert.Equal(ReqChaChaStream, Convert.ToHexStringLower(transport.Written));

        byte[] buffer = new byte[64];
        int read = await stream.ReadAsync(buffer);
        Assert.Equal("hello"u8.ToArray(), buffer[..read]);
        read = await stream.ReadAsync(buffer);
        Assert.Equal(new byte[] { 0x41 }, buffer[..read]);
        Assert.Equal(0, await stream.ReadAsync(buffer));
    }

    [Fact]
    public void UnsupportedSecurity_Throws()
    {
        var transport = new DuplexTestStream([]);

        var ex = Assert.Throws<NotSupportedException>(() =>
            new VmessStream(transport, RequestBodyKey, RequestBodyIv, ResponseBodyKey, ResponseBodyIv,
                (VmessSecurity)VmessRequest.SecurityNone));

        Assert.Contains("5", ex.Message);
    }

    [Fact]
    public void Constructor_WrongKeyOrIvSize_Throws()
    {
        var transport = new DuplexTestStream([]);

        Assert.Throws<ArgumentException>(() =>
            new VmessStream(transport, new byte[15], RequestBodyIv, ResponseBodyKey, ResponseBodyIv,
                VmessSecurity.Aes128Gcm));

        Assert.Throws<ArgumentException>(() =>
            new VmessStream(transport, RequestBodyKey, RequestBodyIv, ResponseBodyKey, new byte[17],
                VmessSecurity.Aes128Gcm));

        Assert.Throws<ArgumentNullException>(() =>
            new VmessStream(null!, RequestBodyKey, RequestBodyIv, ResponseBodyKey, ResponseBodyIv,
                VmessSecurity.Aes128Gcm));
    }

    // ========================= half-close & end-to-end =========================

    [Fact]
    public async Task HalfClose_ReadKeepsWorkingAfterTheWriteDirectionIsClosed()
    {
        var transport = new DuplexTestStream(Hex(RespAesStream));
        var stream = ClientStream(transport);

        await stream.CompleteWriteAsync();
        Assert.True(stream.IsWriteCompleted);
        Assert.False(stream.IsReadCompleted);

        byte[] buffer = new byte[64];
        int read = await stream.ReadAsync(buffer);
        Assert.Equal("hello"u8.ToArray(), buffer[..read]);

        // The two directions keep independent counters.
        Assert.Equal(1, stream.WriteChunkCounter);
        Assert.Equal(1, stream.ReadChunkCounter);
    }

    [Fact]
    public async Task ReadAndWriteDirectionsUseIndependentKeys()
    {
        // Response chunks are sealed with responseBodyKey; feeding the request-keyed
        // chunks to the read direction must fail.
        var transport = new DuplexTestStream(Hex(ReqAesChunk0));
        var stream = ClientStream(transport);

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(async () =>
            await stream.ReadAsync(new byte[64]));
    }

    [Fact]
    public async Task ResponseHeaderThenBody_ReadsAsOneServerStream()
    {
        var transport = new DuplexTestStream(Hex(ResponseHeaderSimple + RespAesStream));

        var header = await VmessResponse.ReadAsync(
            transport, ResponseBodyKey, ResponseBodyIv, RespV, CancellationToken.None);
        Assert.Equal(RespV, header.ResponseVerifier);

        var stream = ClientStream(transport);
        var assembled = new List<byte>();
        byte[] buffer = new byte[64];
        int read;
        while ((read = await stream.ReadAsync(buffer)) > 0)
            assembled.AddRange(buffer[..read]);

        Assert.Equal("helloA"u8.ToArray(), assembled);
        Assert.True(stream.IsReadCompleted);
    }

    [Fact]
    public async Task ReadAndWrite_HonorCancellation()
    {
        var transport = new DuplexTestStream(Hex(RespAesStream));
        var stream = ClientStream(transport);

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await stream.ReadAsync(new byte[64], cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await stream.WriteAsync("hello"u8.ToArray(), cts.Token));
    }

    [Fact]
    public async Task UseAfterDispose_Throws()
    {
        var transport = new DuplexTestStream(Hex(RespAesStream));
        var stream = ClientStream(transport);
        await stream.DisposeAsync();

        Assert.False(stream.CanRead);
        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await stream.ReadAsync(new byte[16]));
        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await stream.WriteAsync("x"u8.ToArray()));
    }

    [Fact]
    public void Constants_MatchSpecSizes()
    {
        Assert.Equal(16, VmessStream.TagSize);
        Assert.Equal(2, VmessStream.LengthPrefixSize);
        Assert.Equal(65535, VmessStream.MaxSealedChunkSize);
        Assert.Equal(65519, VmessStream.MaxReceivePlaintextSize);
        Assert.Equal(8174, VmessStream.MaxSendPlaintextSize);
        Assert.Equal(18, VmessResponse.LengthBlockSize);
        Assert.Equal(4, VmessResponse.MinHeaderSize);
    }
}
