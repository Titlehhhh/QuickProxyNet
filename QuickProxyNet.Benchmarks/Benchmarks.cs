using System;
using System.Text;
using BenchmarkDotNet.Attributes;

namespace QuickProxyNet.Benchmarks;

[MemoryDiagnoser]
public class WriteConnectCommand
{
    public static string Host = "example.com";
    public static int Port = 25565;
    public static string User = "asdnjakgvauyedgfuysgdjfhbsdghfgsdv";
    public static string Pass = "asdklasdkjadhfkjsdhgiuhskfgjdnhsduhfisbfd";

    [Benchmark]
    public byte[] StringBuilderApproach()
    {
        var sb = new StringBuilder(256);
        sb.Append("CONNECT ").Append(Host).Append(':').Append(Port)
          .Append(" HTTP/1.1\r\nHost: ").Append(Host).Append(':').Append(Port).Append("\r\n");
        byte[] credBytes = Encoding.UTF8.GetBytes($"{User}:{Pass}");
        sb.Append("Proxy-Authorization: Basic ").Append(Convert.ToBase64String(credBytes)).Append("\r\n");
        sb.Append("\r\n");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }
}
