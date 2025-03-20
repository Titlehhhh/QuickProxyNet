using System;
using System.Buffers;
using System.Globalization;
using System.Text;
using BenchmarkDotNet;
using BenchmarkDotNet.Attributes;
using Cysharp.Text;
using DotNext;
using DotNext.Buffers;
using DotNext.Buffers.Text;
using DotNext.Text;
using Microsoft.Extensions.Primitives;

namespace QuickProxyNet.Benchmarks
{
    [MemoryDiagnoser]
    public class WriteConnectCommand
    {
        public static string Host = "example.com";
        public static int Port = 25565;

        public static string User = "asdnjakgvauyedgfuysgdjfhbsdghfgsdv";
        public static string Pass = "asdklasdkjadhfkjsdhgiuhskfgjdnhsduhfisbfd";

        private static readonly char[] line1 = "Proxy-Authorization: Basic ".ToCharArray();
        private static readonly char[] newLine = "\r\n".ToCharArray();


        [Benchmark]
        public ReadOnlyMemory<byte> StringBuilder()
        {
            StringBuilder sb = new();
            sb.Append($"CONNECT {Host}:{Port} HTTP/1.1\r\n");
            sb.Append($"Host: {Host}:{Port}\r\n");
            //if (false)
            {
                var token = Encoding.UTF8.GetBytes($"{User}:{Pass}");
                var base64 = Convert.ToBase64String(token);
                sb.Append($"Proxy-Authorization: Basic {base64}\r\n");
                sb.Append("\r\n");
            }

            sb.Append("\r\n");
            string s = sb.ToString();


            return Encoding.UTF8.GetBytes(s.AsSpan()).Memory;
        }

        [Benchmark]
        public ReadOnlyMemory<byte> ZStringBench()
        {
            var builder = ZString.CreateUtf8StringBuilder();
            try
            {
                builder.AppendFormat("CONNECT {0}:{1} HTTP/1.1\r\n", Host, Port);
                builder.AppendFormat("Host: {0}:{1}\r\n", Host, Port);
                // if (false)
                {
                    MemoryOwner<byte> token = Encoding.UTF8.GetBytes($"{User}:{Pass}".AsSpan(), s_allocator);

                    int len = (int)(((uint)token.Length + 2) / 3 * 4);


                    MemoryOwner<char> chars = s_allocator_char.AllocateExactly(len);
                    Convert.TryToBase64Chars(token.Span, chars.Span, out int written);

                    chars.TryResize(written);

                    builder.Append(line1.AsSpan());
                    builder.Append(chars.Span);
                    builder.Append(newLine.AsSpan());

                    chars.Dispose();


                    token.Dispose();
                }

                builder.Append(newLine.AsSpan());
                return builder.AsMemory();
            }
            finally
            {
                builder.Dispose();
            }
        }

        private static MemoryAllocator<byte> s_allocator = ArrayPool<byte>.Shared.ToAllocator();
        private static MemoryAllocator<char> s_allocator_char = ArrayPool<char>.Shared.ToAllocator();

        [Benchmark]
        public ReadOnlyMemory<byte> DotNext1()
        {
            scoped BufferWriterSlim<char> writer = new BufferWriterSlim<char>();

            writer.Interpolate($"CONNECT {Host}:{Host} HTTP/1.1\r\n");
            writer.Interpolate($"Host: {Host}:{Host}\r\n");
            //if (false)
            {
                MemoryOwner<byte> token = Encoding.UTF8.GetBytes($"{User}:{Pass}".AsSpan(), s_allocator);

                int len = (int)(((uint)token.Length + 2) / 3 * 4);
                writer.Write(line1);

                Base64Encoder encoder = new Base64Encoder();

                encoder.EncodeToUtf16(token.Span, ref writer, true);

                writer.Write(newLine);


                encoder.Reset();
                token.Dispose();
            }

            writer.Write(newLine);
            try
            {
                return Encoding.UTF8.GetBytes(writer.WrittenSpan, s_allocator).Memory;
            }
            finally
            {
                writer.Dispose();
            }
        }
    }
}