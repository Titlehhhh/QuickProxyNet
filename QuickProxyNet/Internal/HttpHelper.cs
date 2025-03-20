using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Cysharp.Text;
using DotNext;
using DotNext.Buffers;
using DotNext.Text;

namespace QuickProxyNet;

internal static class HttpHelper
{
    private static readonly char[] line1 = "Proxy-Authorization: Basic ".ToCharArray();
    private static readonly char[] newLine = "\r\n".ToCharArray();

    private static MemoryAllocator<byte> s_allocator = ArrayPool<byte>.Shared.ToAllocator();
    private static MemoryAllocator<char> s_allocator_char = ArrayPool<char>.Shared.ToAllocator();

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static async ValueTask WriteConnectionCommand(Stream stream, string host, int port,
        NetworkCredential? proxyCredentials, CancellationToken cancellationToken)
    {
        var builder = ZString.CreateUtf8StringBuilder();
        try
        {
            builder.AppendFormat("CONNECT {0}:{1} HTTP/1.1\r\n", host, port);
            builder.AppendFormat("Host: {0}:{1}\r\n", host, port);

            if (proxyCredentials is not null)
            {
                MemoryOwner<byte> token =
                    Encoding.UTF8.GetBytes($"{proxyCredentials.UserName}:{proxyCredentials.Password}".AsSpan(),
                        s_allocator);

                int len = (int)(((uint)token.Length + 2) / 3 * 4);

                MemoryOwner<char> chars = s_allocator_char.AllocateExactly(len);
                Convert.TryToBase64Chars(token.Span, chars.Span, out int written);
                chars.TryResize(written);
                builder.Append(line1.AsSpan());
                builder.Append(chars.Span);
                builder.Append("\r\n");
                chars.Dispose();
                token.Dispose();
            }

            builder.Append("\r\n");


            await stream.WriteAsync(builder.AsMemory(), cancellationToken);
        }
        finally
        {
            builder.Dispose();
        }
    }


    internal static async ValueTask<Stream> EstablishHttpTunnelAsync(Stream stream, Uri proxyUri, string host, int port,
        NetworkCredential? credentials, CancellationToken cancellationToken)
    {
        await WriteConnectionCommand(stream, host, port, credentials, cancellationToken);


        var parser = new HttpResponseParser();
        try
        {
            bool find;
            do
            {
                var memory = parser.GetMemory();
                var nread = await stream.ReadAsync(memory, cancellationToken);
                if (nread <= 0)
                    throw new EndOfStreamException();
                find = parser.Parse(nread);
            } while (find == false);

            bool isValid = parser.Validate();
#if DEBUG
            string response = parser.ToString();
#endif


            if (!isValid)
            {
                throw new ProxyProtocolException($"Failed to connect {host}:{port}");
            }

            return stream;
        }
        finally
        {
            parser.Dispose();
        }
    }
}