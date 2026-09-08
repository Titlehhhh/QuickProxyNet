using System.Reflection;
using System.Security.Cryptography;
using Xunit.Sdk;

namespace QuickProxyNet.Tests;

/// <summary>
/// Environment switches that gate the integration tests, and the one place that reads them.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why attributes and not a runtime <c>Assert.Skip</c>.</b> xunit.assert 2.9.3 does export
/// <c>Xunit.Sdk.SkipException.ForSkip(string)</c>, so <c>throw SkipException.ForSkip(...)</c>
/// compiles — but it does not work. Dynamic skip is a v3 feature: the <c>$XunitDynamicSkip$</c>
/// message token appears in <b>no</b> v2 assembly (verified by scanning xunit.core 2.9.3,
/// xunit.execution.dotnet 2.9.3 and xunit.runner.visualstudio 3.0.0), so v2 reports the throw as
/// a plain <b>failure</b> with the raw token in the message. <c>Assert.Skip</c> /
/// <c>Assert.SkipWhen</c> / <c>Assert.SkipUnless</c> are not even present in the 2.9.3 assembly —
/// they sit behind the <c>XUNIT_SKIP</c> compilation define that only v3 sets.
/// </para>
/// <para>
/// What v2 <i>does</i> support is <see cref="FactAttribute.Skip"/> decided at discovery time.
/// Environment variables do not change during a test run, so evaluating the gate in the
/// attribute constructor is exact, and it produces a real <b>skipped</b> result.
/// </para>
/// <para>
/// The rule this enforces: a test whose prerequisites are missing reports as <b>skipped</b>,
/// never as passed. An early <c>return</c> turns "did not run" into "green", which is how a
/// suite starts lying about what it proves.
/// </para>
/// </remarks>
internal static class SkipGates
{
    /// <summary>Set to <c>1</c> to run the docker-backed protocol integration tests.</summary>
    public const string DockerSwitch = "QPN_DOCKER_TESTS";

    /// <summary>True when the docker integration tests are enabled.</summary>
    public static bool DockerEnabled =>
        string.Equals(Environment.GetEnvironmentVariable(DockerSwitch), "1", StringComparison.Ordinal);

    /// <summary>True when <paramref name="name"/> is set to a non-empty value.</summary>
    public static bool IsSet(string name) =>
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name));

    /// <summary>
    /// The skip reason for a test that needs <b>all</b> of <paramref name="names"/>, or null
    /// when they are all set.
    /// </summary>
    public static string? RequireAll(string[] names)
    {
        List<string>? missing = null;
        foreach (string name in names)
        {
            if (!IsSet(name))
                (missing ??= []).Add(name);
        }

        return missing is null ? null : $"Not set: {string.Join(", ", missing)}.";
    }

    /// <summary>
    /// The skip reason for a test that needs <b>any</b> of <paramref name="names"/>, or null
    /// when at least one is set.
    /// </summary>
    public static string? RequireAny(string[] names)
    {
        foreach (string name in names)
        {
            if (IsSet(name))
                return null;
        }

        return $"None of these is set: {string.Join(", ", names)}.";
    }
}

/// <summary>
/// A <see cref="FactAttribute"/> that reports the test as <b>skipped</b> unless every named
/// environment variable is set to a non-empty value.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class EnvFactAttribute : FactAttribute
{
    /// <param name="requiredVariables">Environment variables that must all be set.</param>
    public EnvFactAttribute(params string[] requiredVariables) =>
        Skip = SkipGates.RequireAll(requiredVariables);
}

/// <summary>
/// A <see cref="TheoryAttribute"/> that reports the test as <b>skipped</b> unless every named
/// environment variable is set to a non-empty value. The theory counterpart of
/// <see cref="EnvFactAttribute"/>: a <c>[Theory]</c> that returns early when the variable is
/// missing reports as passed, which is the one outcome a gate exists to prevent.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class EnvTheoryAttribute : TheoryAttribute
{
    /// <param name="requiredVariables">Environment variables that must all be set.</param>
    public EnvTheoryAttribute(params string[] requiredVariables) =>
        Skip = SkipGates.RequireAll(requiredVariables);
}

/// <summary>
/// A <see cref="FactAttribute"/> that reports the test as <b>skipped</b> unless at least one of
/// the named environment variables is set to a non-empty value.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class AnyEnvFactAttribute : FactAttribute
{
    /// <param name="acceptedVariables">Environment variables, any one of which enables the test.</param>
    public AnyEnvFactAttribute(params string[] acceptedVariables) =>
        Skip = SkipGates.RequireAny(acceptedVariables);
}

/// <summary>
/// A <see cref="FactAttribute"/> gated on <c>QPN_DOCKER_TESTS=1</c>. Reports as <b>skipped</b>
/// when the docker integration tests are not enabled.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class DockerFactAttribute : FactAttribute
{
    /// <summary>Creates the attribute, deciding the skip state from the environment.</summary>
    public DockerFactAttribute() =>
        Skip = SkipGates.DockerEnabled ? null : $"{SkipGates.DockerSwitch} is not set to 1.";
}

/// <summary>
/// A <see cref="TheoryAttribute"/> gated on <c>QPN_DOCKER_TESTS=1</c>. Reports as <b>skipped</b>
/// when the docker integration tests are not enabled.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class DockerTheoryAttribute : TheoryAttribute
{
    /// <summary>Creates the attribute, deciding the skip state from the environment.</summary>
    public DockerTheoryAttribute() =>
        Skip = SkipGates.DockerEnabled ? null : $"{SkipGates.DockerSwitch} is not set to 1.";
}

/// <summary>
/// An <c>[InlineData]</c> row that reports as <b>skipped</b> when the OS does not provide
/// ChaCha20-Poly1305 (<see cref="ChaCha20Poly1305.IsSupported"/> — false on every Windows 10).
/// </summary>
/// <remarks>
/// The theory's other rows still run. This exists so a cipher theory can cover
/// <c>chacha20-ietf-poly1305</c> without an early <c>return</c> inside the test body, which
/// would report "did not run" as passed. xunit v2 honours <see cref="DataAttribute.Skip"/> at
/// discovery time, the same mechanism <see cref="DockerFactAttribute"/> relies on.
/// </remarks>
[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
public sealed class ChaCha20InlineDataAttribute : DataAttribute
{
    private readonly object[] _data;

    /// <param name="data">The row's arguments.</param>
    public ChaCha20InlineDataAttribute(params object[] data)
    {
        _data = data;
        Skip = ChaCha20Poly1305.IsSupported
            ? null
            : "ChaCha20-Poly1305 is not available on this OS (Windows needs build 20142 or later).";
    }

    /// <inheritdoc />
    public override IEnumerable<object[]> GetData(MethodInfo testMethod) => [_data];
}
