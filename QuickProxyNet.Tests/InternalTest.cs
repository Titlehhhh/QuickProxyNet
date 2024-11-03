using System.Text;
using DotNext.Buffers;
using Span = DotNext.Span;

namespace QuickProxyNet.Tests;

public class HttpResponseParserTest
{
    [Fact]
    public void ParseHttp1_0()
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("HTTP/1.0 200 OK");
        sb.AppendLine();

        Span<byte> bytes = Encoding.UTF8.GetBytes(sb.ToString());


        HttpResponseParser parser = new HttpResponseParser();
        try
        {
            Memory<byte> memory = parser.GetMemory();

            bytes.CopyTo(memory.Span);

            int writtenBytes = Math.Min(bytes.Length, memory.Length);

            bool b = parser.Parse(writtenBytes);

            Assert.True(b);

            Assert.Equal(sb.ToString(), parser.GetString());
        }
        finally
        {
            parser.Dispose();
        }
    }

    [Fact]
    public void ParseHttp1_1()
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("HTTP/1.1 200 OK");
        sb.AppendLine();

        Span<byte> bytes = Encoding.UTF8.GetBytes(sb.ToString());


        HttpResponseParser parser = new HttpResponseParser();
        try
        {
            Memory<byte> memory = parser.GetMemory();

            bytes.CopyTo(memory.Span);

            int writtenBytes = Math.Min(bytes.Length, memory.Length);

            bool b = parser.Parse(writtenBytes);

            Assert.True(b);

            Assert.Equal(sb.ToString(), parser.GetString());
        }
        finally
        {
            parser.Dispose();
        }
    }

    [Fact]
    public void ParseOneNewLine()
    {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("HTTP/1.1 200 OK");
        //sb.AppendLine();

        Span<byte> bytes = Encoding.UTF8.GetBytes(sb.ToString());


        HttpResponseParser parser = new HttpResponseParser();
        try
        {
            Memory<byte> memory = parser.GetMemory();

            bytes.CopyTo(memory.Span);

            int writtenBytes = Math.Min(bytes.Length, memory.Length);

            bool b = parser.Parse(writtenBytes);

            Assert.False(b);

            Assert.Equal(sb.ToString(), parser.GetString());
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
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("HTTP/1.1 200 Connection established");
        sb.AppendLine();

        Span<byte> bytes = Encoding.UTF8.GetBytes(sb.ToString());
        HttpResponseParser parser = new HttpResponseParser();
        while (true)
        {
            Memory<byte> memory = parser.GetMemory();

            var length = Math.Min(memory.Length, Math.Min(segmentLength, bytes.Length));
            
            Span<byte> writtenBytes = bytes.Slice(0, length);

            writtenBytes.CopyTo(memory.Span);
            bool b = parser.Parse(writtenBytes.Length);
            string gg = parser.GetString();

            bytes = bytes.Slice(length);

            if (b)
                break;
        }

        bool isValid = parser.Validate();

        Assert.True(isValid);
        Assert.Equal(sb.ToString(), parser.ToString());
    }
}