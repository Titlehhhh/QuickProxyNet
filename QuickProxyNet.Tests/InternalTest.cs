using System.Text;

namespace QuickProxyNet.Tests;

public class HttpResponseParserTest
{
    [Fact]
    public void ParseHttp1_0()
    {
        // Use explicit \r\n (HTTP protocol line endings), NOT AppendLine which uses OS newline
        var raw = "HTTP/1.0 200 OK\r\n\r\n";
        Span<byte> bytes = Encoding.UTF8.GetBytes(raw);

        HttpResponseParser parser = new HttpResponseParser();
        try
        {
            Memory<byte> memory = parser.GetMemory();
            bytes.CopyTo(memory.Span);
            bool b = parser.Parse(bytes.Length);

            Assert.True(b);
            Assert.Equal(raw, parser.ToString());
        }
        finally
        {
            parser.Dispose();
        }
    }

    [Fact]
    public void ParseHttp1_1()
    {
        var raw = "HTTP/1.1 200 OK\r\n\r\n";
        Span<byte> bytes = Encoding.UTF8.GetBytes(raw);

        HttpResponseParser parser = new HttpResponseParser();
        try
        {
            Memory<byte> memory = parser.GetMemory();
            bytes.CopyTo(memory.Span);
            bool b = parser.Parse(bytes.Length);

            Assert.True(b);
            Assert.Equal(raw, parser.ToString());
        }
        finally
        {
            parser.Dispose();
        }
    }

    [Fact]
    public void ParseOneNewLine()
    {
        // Only one \r\n — no end-of-headers marker
        var raw = "HTTP/1.1 200 OK\r\n";
        Span<byte> bytes = Encoding.UTF8.GetBytes(raw);

        HttpResponseParser parser = new HttpResponseParser();
        try
        {
            Memory<byte> memory = parser.GetMemory();
            bytes.CopyTo(memory.Span);
            bool b = parser.Parse(bytes.Length);

            Assert.False(b);
            Assert.Equal(raw, parser.ToString());
        }
        finally
        {
            parser.Dispose();
        }
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void ParseSegments(int segmentLength)
    {
        var raw = "HTTP/1.1 200 Connection established\r\n\r\n";
        Span<byte> bytes = Encoding.UTF8.GetBytes(raw);

        HttpResponseParser parser = new HttpResponseParser();
        try
        {
            while (bytes.Length > 0)
            {
                Memory<byte> memory = parser.GetMemory();
                var length = Math.Min(memory.Length, Math.Min(segmentLength, bytes.Length));
                bytes[..length].CopyTo(memory.Span);
                bool b = parser.Parse(length);

                bytes = bytes[length..];

                if (b)
                {
                    Assert.True(parser.GetStatusCode() == 200);
                    Assert.Equal(raw, parser.ToString());
                    return;
                }
            }

            Assert.Fail("Parser did not find end of headers");
        }
        finally
        {
            parser.Dispose();
        }
    }

    [Fact]
    public void GetStatusCode_Various()
    {
        var cases = new[] { ("HTTP/1.1 200 OK\r\n\r\n", 200), ("HTTP/1.1 407 Auth\r\n\r\n", 407), ("HTTP/1.0 503 Unavailable\r\n\r\n", 503) };

        foreach (var (raw, expectedCode) in cases)
        {
            var parser = new HttpResponseParser();
            try
            {
                var bytes = Encoding.UTF8.GetBytes(raw).AsSpan();
                parser.GetMemory().Span[..bytes.Length].CopyTo(parser.GetMemory().Span);
                bytes.CopyTo(parser.GetMemory().Span);
                parser.Parse(bytes.Length);
                Assert.Equal(expectedCode, parser.GetStatusCode());
            }
            finally
            {
                parser.Dispose();
            }
        }
    }

    [Fact]
    public void GetStatusCode_Malformed_ReturnsNegativeOne()
    {
        var parser = new HttpResponseParser();
        try
        {
            var bytes = "GARBAGE\r\n\r\n"u8;
            bytes.CopyTo(parser.GetMemory().Span);
            parser.Parse(bytes.Length);
            Assert.Equal(-1, parser.GetStatusCode());
        }
        finally
        {
            parser.Dispose();
        }
    }

    [Fact]
    public void HasOverreadBytes_WhenExtraBytesAfterHeaders()
    {
        var parser = new HttpResponseParser();
        try
        {
            var raw = "HTTP/1.1 200 OK\r\n\r\nEXTRA"u8;
            raw.CopyTo(parser.GetMemory().Span);
            bool found = parser.Parse(raw.Length);

            Assert.True(found);
            Assert.True(parser.HasOverreadBytes);
            Assert.Equal("EXTRA"u8.ToArray(), parser.OverreadBytes.ToArray());
        }
        finally
        {
            parser.Dispose();
        }
    }

    [Fact]
    public void HasOverreadBytes_NoExtra_ReturnsFalse()
    {
        var parser = new HttpResponseParser();
        try
        {
            var raw = "HTTP/1.1 200 OK\r\n\r\n"u8;
            raw.CopyTo(parser.GetMemory().Span);
            parser.Parse(raw.Length);

            Assert.False(parser.HasOverreadBytes);
            Assert.True(parser.OverreadBytes.IsEmpty);
        }
        finally
        {
            parser.Dispose();
        }
    }

    [Fact]
    public void GetMemory_ThrowsWhenMaxHeaderSizeExceeded()
    {
        var parser = new HttpResponseParser();
        try
        {
            // Feed 16 KB of header-like data without \r\n\r\n
            var chunk = "X-Header: value\r\n"u8;
            while (true)
            {
                Memory<byte> mem;
                try
                {
                    mem = parser.GetMemory();
                }
                catch (ProxyProtocolException ex)
                {
                    Assert.Equal(ProxyErrorCode.InvalidResponse, ex.ErrorCode);
                    return; // expected
                }

                int len = Math.Min(chunk.Length, mem.Length);
                chunk[..len].CopyTo(mem.Span);
                parser.Parse(len);
            }
        }
        finally
        {
            parser.Dispose();
        }
    }
}
