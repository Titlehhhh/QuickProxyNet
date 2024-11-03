using System.Net;
using System.Net.Sockets;
using System.Text;
using QuickProxyNet;

namespace Sample;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("Enter proxy uri (protocol://<login?>:<pass?>@host:port");
        string? proxyUri = Console.ReadLine();

        if (string.IsNullOrEmpty(proxyUri))
            return;

        Uri uri = new Uri(proxyUri);

        ProxyClientFactory factory = new ProxyClientFactory();

        IProxyClient proxyClient = factory.Create(uri);

        Stream stream = await proxyClient.ConnectAsync("example.com", 80); // 80 for HTTP


        HttpRequestMessage requestMessage = new HttpRequestMessage();

        requestMessage.Method = HttpMethod.Get;
        requestMessage.RequestUri = new Uri("https://www.example.com/");

        string rawString = await ToRawString(requestMessage);

        byte[] bytes = Encoding.UTF8.GetBytes(rawString);

        await stream.WriteAsync(bytes);

        using StreamReader sr = new StreamReader(stream);
        while (!sr.EndOfStream)
        {
            var line = await sr.ReadLineAsync();
            if (!string.IsNullOrEmpty(line))
            {
                Console.WriteLine(line);
            }
        }
    }

    public static async Task<string> ToRawString(HttpRequestMessage request)
    {
        var sb = new StringBuilder();

        var line1 = $"{request.Method} {request.RequestUri} HTTP/{request.Version}";
        sb.AppendLine(line1);

        foreach (var (key, value) in request.Headers)
        foreach (var val in value)
        {
            var header = $"{key}: {val}";
            sb.AppendLine(header);
        }

        if (request.Content?.Headers != null)
        {
            foreach (var (key, value) in request.Content.Headers)
            foreach (var val in value)
            {
                var header = $"{key}: {val}";
                sb.AppendLine(header);
            }
        }

        sb.AppendLine();

        var body = await (request.Content?.ReadAsStringAsync() ?? Task.FromResult<string>(null));
        if (!string.IsNullOrWhiteSpace(body))
            sb.AppendLine(body);

        return sb.ToString();
    }
}