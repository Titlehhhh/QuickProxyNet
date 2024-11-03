using System.Net;

namespace QuickProxyNet.Tests;

public class FactoryTest
{
    [Theory]
    [InlineData("ftp://exampleproxy.com:5004")]
    public void BadProtocolUri(string stringUri)
    {
        Uri uri = new Uri(stringUri);

        ProxyClientFactory factory = new ProxyClientFactory();

        try
        {
            factory.Create(uri);
        }
        catch (Exception e)
        {
            Assert.IsType<NotSupportedException>(e);
        }
    }

    [Theory]
    [InlineData("http://exampleproxy.com:5004")]
    [InlineData("https://exampleproxy.com:5003")]
    [InlineData("socks4://exampleproxy.com:5002")]
    [InlineData("socks4a://exampleproxy.com:5001")]
    [InlineData("socks5://exampleproxy.com:5000")]
    public void TestCreateFromUri(string stringUri)
    {
        Uri uri = new Uri(stringUri);


        ProxyClientFactory factory = new ProxyClientFactory();

        IProxyClient client = factory.Create(uri);


        Assert.Equal(client.Type.ToString().ToLower(), uri.Scheme.ToLower());
        Assert.Equal(client.ProxyHost, uri.Host);
        Assert.Equal(client.ProxyPort, uri.Port);
        Assert.Null(client.ProxyCredentials);
    }

    [Theory]
    [InlineData("http://MyLogin:MyPass@exampleproxy.com:5004")]
    [InlineData("https://MyLogin:MyPass@exampleproxy.com:5003")]
    [InlineData("socks4://MyLogin:MyPass@exampleproxy.com:5002")]
    [InlineData("socks4a://MyLogin:MyPass@exampleproxy.com:5001")]
    [InlineData("socks5://MyLogin:MyPass@exampleproxy.com:5000")]
    public void TestCreateFromUriWithPass(string stringUri)
    {
        Uri uri = new Uri(stringUri);


        ProxyClientFactory factory = new ProxyClientFactory();

        IProxyClient client = factory.Create(uri);


        Assert.Equal(client.Type.ToString().ToLower(), uri.Scheme.ToLower());
        Assert.Equal(client.ProxyHost, uri.Host);
        Assert.Equal(client.ProxyPort, uri.Port);

        Assert.NotNull(client.ProxyCredentials);
        string actual = $"{client.ProxyCredentials.UserName}:{client.ProxyCredentials.Password}";

        Assert.Equal("MyLogin:MyPass", actual);
    }
}