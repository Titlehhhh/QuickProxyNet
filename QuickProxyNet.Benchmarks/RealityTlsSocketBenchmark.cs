using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Toolchains.InProcess.NoEmit;

namespace QuickProxyNet.Benchmarks;

/// <summary>
/// Steady-state throughput of <see cref="RealityTlsStream"/> over a real loopback TCP socket.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="RealityTlsStreamBenchmark"/> runs the same traffic over memory, which measures the
/// AEAD and the framing and nothing else. What it cannot see is the cost this layer actually
/// controls: how many times it goes to the transport. A record is a 5-byte header and a body, and
/// a layer that asks for those separately pays two reads per record; a 64 KiB write that becomes
/// four records and four writes pays four times to satisfy one caller. Against memory those are
/// virtual calls and cost nothing. Against a socket they are syscalls.
/// </para>
/// <para>
/// So: a real connected socket pair on loopback, 1 MiB per operation, which makes the
/// <c>Allocated</c> column read as bytes allocated per MiB transferred. It is still loopback and
/// not a network — no bandwidth-delay product, no loss — so it measures the syscall and copy
/// cost, which is the part this code decides.
/// </para>
/// <para>
/// <c>Write_1MiB</c> writes to a peer that does nothing but drain. <c>RoundTrip_1MiB</c> uses a
/// peer that echoes the bytes back verbatim: the client's read protection is a second instance
/// built from the same traffic secret, so it opens the very records it sealed, in order, with the
/// sequence numbers staying in lockstep. Reading runs concurrently with writing because it has
/// to — a megabyte does not fit in a socket buffer, and a write-then-read client deadlocks
/// against an echo peer that is blocked writing back.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
[Config(typeof(Config))]
public class RealityTlsSocketBenchmark
{
    private class Config : ManualConfig
    {
        public Config() =>
            AddJob(Job.ShortRun.WithIterationCount(5).WithToolchain(InProcessNoEmitToolchain.Instance));
    }

    private const int Payload = 1024 * 1024;
    private const ushort Aes128Gcm = 0x1301;

    private byte[] _data = null!;
    private byte[] _readBuffer = null!;

    private Socket _listener = null!;
    private Peer _drain = null!;
    private Peer _echo = null!;

    private RealityTlsStream _sink = null!;
    private RealityTlsStream _client = null!;

    /// <summary>One end of a loopback pair, plus the task servicing it.</summary>
    private sealed class Peer : IDisposable
    {
        private readonly CancellationTokenSource _stopping = new();

        public Peer(Socket client, Socket server, bool echo)
        {
            Client = client;
            Server = server;
            Service = ServiceAsync(server, echo, _stopping.Token);
        }

        public Socket Client { get; }
        public Socket Server { get; }
        public Task Service { get; }

        private static async Task ServiceAsync(Socket server, bool echo, CancellationToken stopping)
        {
            byte[] buffer = new byte[64 * 1024];

            try
            {
                while (!stopping.IsCancellationRequested)
                {
                    int read = await server.ReceiveAsync(buffer, SocketFlags.None, stopping);
                    if (read == 0)
                        return;

                    if (echo)
                        await SendAllAsync(server, buffer.AsMemory(0, read), stopping);
                }
            }
            catch (OperationCanceledException)
            {
                // The benchmark is over; the peer is meant to stop here.
            }
            catch (SocketException)
            {
                // The client end was closed first, which is how this ends in practice.
            }
        }

        private static async Task SendAllAsync(Socket socket, ReadOnlyMemory<byte> data, CancellationToken stopping)
        {
            while (!data.IsEmpty)
            {
                int sent = await socket.SendAsync(data, SocketFlags.None, stopping);
                data = data[sent..];
            }
        }

        public void Dispose()
        {
            _stopping.Cancel();

            try
            {
                Client.Dispose();
                Server.Dispose();
            }
            catch (SocketException)
            {
                // Already torn down.
            }

            _stopping.Dispose();
        }
    }

    private Peer Connect(bool echo)
    {
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        client.Connect((IPEndPoint)_listener.LocalEndPoint!);
        Socket server = _listener.Accept();

        // Nagle would coalesce our writes for us and measure the kernel's batching instead of
        // ours, which is the opposite of the point.
        client.NoDelay = true;
        server.NoDelay = true;

        return new Peer(client, server, echo);
    }

    [GlobalSetup]
    public void Setup()
    {
        TlsCipherSuite suite = TlsCipherSuite.FromId(Aes128Gcm)!;

        Span<byte> sinkSecret = stackalloc byte[suite.HashLength];
        Span<byte> pairSecret = stackalloc byte[suite.HashLength];
        RandomNumberGenerator.Fill(sinkSecret);
        RandomNumberGenerator.Fill(pairSecret);

        _data = new byte[Payload];
        RandomNumberGenerator.Fill(_data);
        _readBuffer = new byte[TlsRecordStream.MaxPlaintext];

        _listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _listener.Listen(2);

        _drain = Connect(echo: false);
        _echo = Connect(echo: true);

        // One NetworkStream per socket, shared by the record layer and the stream above it: two
        // instances over one socket would be two buffers and two disposal paths for one endpoint.
        var drainTransport = new NetworkStream(_drain.Client, ownsSocket: false);
        var sinkRecords = new TlsRecordStream(drainTransport)
        {
            Write = new TlsRecordProtection(suite, sinkSecret)
        };
        _sink = new RealityTlsStream(drainTransport, sinkRecords, []);

        var echoTransport = new NetworkStream(_echo.Client, ownsSocket: false);
        var clientRecords = new TlsRecordStream(echoTransport)
        {
            Write = new TlsRecordProtection(suite, pairSecret),
            Read = new TlsRecordProtection(suite, pairSecret)
        };
        _client = new RealityTlsStream(echoTransport, clientRecords, []);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _sink.Dispose();
        _client.Dispose();
        _drain.Dispose();
        _echo.Dispose();
        _listener.Dispose();
    }

    /// <summary>Seal, frame and send 1 MiB — 64 full-size records — to a peer that only drains.</summary>
    [Benchmark]
    [BenchmarkCategory("Write")]
    public async Task Write_1MiB() =>
        await _sink.WriteAsync(_data.AsMemory(), CancellationToken.None);

    /// <summary>Send 1 MiB and read the same megabyte back off the wire.</summary>
    [Benchmark]
    [BenchmarkCategory("RoundTrip")]
    public async Task<int> RoundTrip_1MiB()
    {
        Task<int> reading = ReadAsync();

        await _client.WriteAsync(_data.AsMemory(), CancellationToken.None);

        return await reading;

        async Task<int> ReadAsync()
        {
            int total = 0;
            while (total < Payload)
            {
                int read = await _client.ReadAsync(_readBuffer.AsMemory(), CancellationToken.None);
                if (read == 0)
                    throw new InvalidOperationException("The peer closed the connection early.");

                total += read;
            }

            return total;
        }
    }
}
