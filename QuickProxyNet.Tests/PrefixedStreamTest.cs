using System.Text;

namespace QuickProxyNet.Tests;

public class PrefixedStreamTest
{
    /// <summary>
    /// Creates a PrefixedStream by sending HTTP 200 + overread bytes through HttpHelper.
    /// This is the only way to construct one since the class is private.
    /// </summary>
    private static async Task<Stream> CreatePrefixedStreamAsync(byte[] overreadBytes, Stream innerStream)
    {
        var responseText = "HTTP/1.1 200 Connection established\r\n\r\n";
        var responseBytes = Encoding.UTF8.GetBytes(responseText);
        var combined = new byte[responseBytes.Length + overreadBytes.Length];
        responseBytes.CopyTo(combined, 0);
        overreadBytes.CopyTo(combined, responseBytes.Length);

        var fakeStream = new Helpers.FakeProxyStream(combined);
        var result = await HttpHelper.EstablishHttpTunnelAsync(
            fakeStream, new Uri("http://proxy:8080"), "target", 443, null, CancellationToken.None);
        return result;
    }

    [Fact]
    public async Task Read_ReturnsPrefixBytesFirst_ThenInnerStream()
    {
        var overread = "HELLO"u8.ToArray();
        var prefixed = await CreatePrefixedStreamAsync(overread, Stream.Null);

        var buf = new byte[20];
        int read = await prefixed.ReadAsync(buf);
        Assert.Equal(5, read);
        Assert.Equal("HELLO", Encoding.UTF8.GetString(buf, 0, read));
    }

    [Fact]
    public async Task Read_SmallBuffer_ReturnsPartialPrefix()
    {
        var overread = "ABCDEF"u8.ToArray();
        var prefixed = await CreatePrefixedStreamAsync(overread, Stream.Null);

        // Read only 3 bytes at a time
        var buf = new byte[3];
        int read1 = await prefixed.ReadAsync(buf);
        Assert.Equal(3, read1);
        Assert.Equal("ABC", Encoding.UTF8.GetString(buf, 0, read1));

        int read2 = await prefixed.ReadAsync(buf);
        Assert.Equal(3, read2);
        Assert.Equal("DEF", Encoding.UTF8.GetString(buf, 0, read2));
    }

    [Fact]
    public async Task SyncRead_ReturnsPrefixBytesFirst()
    {
        var overread = "SYNC"u8.ToArray();
        var prefixed = await CreatePrefixedStreamAsync(overread, Stream.Null);

        var buf = new byte[10];
        int read = prefixed.Read(buf);
        Assert.Equal(4, read);
        Assert.Equal("SYNC", Encoding.UTF8.GetString(buf, 0, read));
    }

    [Fact]
    public async Task CanRead_IsTrue()
    {
        var overread = "X"u8.ToArray();
        var prefixed = await CreatePrefixedStreamAsync(overread, Stream.Null);
        Assert.True(prefixed.CanRead);
    }

    [Fact]
    public async Task CanSeek_IsFalse()
    {
        var overread = "X"u8.ToArray();
        var prefixed = await CreatePrefixedStreamAsync(overread, Stream.Null);
        Assert.False(prefixed.CanSeek);
    }
}
