using System;
using System.Linq;
using Nuke.Common;
using Nuke.Common.Execution;
using Nuke.Common.Git;
using Nuke.Common.IO;
using Nuke.Common.ProjectModel;
using Nuke.Common.Tooling;
using Nuke.Common.Tools.DotNet;
using Nuke.Common.Tools.GitVersion;
using Nuke.Common.Utilities.Collections;
using Serilog;
using static Nuke.Common.EnvironmentInfo;
using static Nuke.Common.IO.FileSystemTasks;
using static Nuke.Common.IO.PathConstruction;
using static Nuke.Common.Tools.DotNet.DotNetTasks;


class Build : NukeBuild
{
    /// Support plugins are available for:
    ///   - JetBrains ReSharper        https://nuke.build/resharper
    ///   - JetBrains Rider            https://nuke.build/rider
    ///   - Microsoft VisualStudio     https://nuke.build/visualstudio
    ///   - Microsoft VSCode           https://nuke.build/vscode
    [Solution(GenerateProjects = true)]
    readonly Solution Solution;

    [NuGetPackage("Meziantou.Framework.NuGetPackageValidation.Tool",
        "Meziantou.Framework.NuGetPackageValidation.Tool.dll", Framework = "net8.0")]
    Tool ValidationTool;

    [GitRepository] readonly GitRepository GitRepository;
    [GitVersion] readonly GitVersion GitVersion;

    [Parameter] string NugetApiUrl = "https://api.nuget.org/v3/index.json";
    [Parameter] string NugetApiKey;
    [Parameter] string GithubApiKey;
    public static int Main() => Execute<Build>(x => x.Compile);

    [Parameter("Configuration to build - Default is 'Debug' (local) or 'Release' (server)")]
    readonly Configuration Configuration = IsLocalBuild ? Configuration.Debug : Configuration.Release;

    AbsolutePath SourceDirectory => RootDirectory / "src";
    AbsolutePath TestsDirectory => RootDirectory / "tests";
    AbsolutePath AnalyzerDirectory => RootDirectory / "analyzers";
    AbsolutePath ArtifactsDirectory => RootDirectory / "artifacts";
    AbsolutePath NugetDirectory => ArtifactsDirectory / "nuget";

    Target Tests => _ => _
        .DependsOn(Compile)
        .Executes(() =>
        {
            DotNetTest(x =>
                x.SetProjectFile(Solution.QuickProxyNet_Tests));
        });

    Target Clean => _ => _
        .Before(Restore)
        .Executes(() =>
        {
            ArtifactsDirectory.DeleteDirectory();
            NugetDirectory.DeleteDirectory();
        });

    Target Restore => _ => _
        .DependsOn(Clean)
        .Executes(() =>
        {
            DotNetRestore(_ => _
                .SetProjectFile(Solution));
        });

    Target PrintVersion => _ => _
        .Executes(() =>
        {
            Log.Information(GitVersion.FullSemVer);
            Log.Information(GitVersion.NuGetVersionV2);
        });

    Target Compile => _ => _
        .DependsOn(Restore)
        .Executes(() =>
        {
            DotNetBuild(_ => _
                .SetProjectFile(Solution)
                .SetConfiguration(Configuration)
                .SetAssemblyVersion(GitVersion.AssemblySemVer)
                .SetFileVersion(GitVersion.AssemblySemFileVer)
                .SetInformationalVersion(GitVersion.InformationalVersion)
                .EnableNoRestore());
        });


    Target Validation => _ => _
        .DependsOn(Pack)
        .Executes(() =>
        {
            NugetDirectory.GlobFiles("*.nupkg")
                .ForEach(x =>
                {
                    ValidationTool.Invoke(x.ToString());
                    
                });
        });

    Target Pack => _ => _
        .DependsOn(Tests)
        .Requires(() => Configuration.Equals(Configuration.Release))
        .Executes(() =>
        {
            DotNetPack(s => s
                .SetProject(Solution.QuickProxyNet)
                .SetConfiguration(Configuration)
                .SetVersion(GitVersion.NuGetVersionV2)
                .SetNoDependencies(true)
                .SetContinuousIntegrationBuild(true)
                .SetOutputDirectory(ArtifactsDirectory / "nuget"));
        });

    Target Push => _ => _
        .DependsOn(Pack)
        .DependsOn(Validation)
        .DependsOn(Tests)
        .Requires(() => NugetApiUrl)
        .Requires(() => NugetApiKey)
        .Requires(()=> GithubApiKey)
        .Requires(() => Configuration.Equals(Configuration.Release))
        .Executes(() =>
        {
            string apiKey = NugetApiUrl == "https://api.nuget.org/v3/index.json" ? NugetApiKey : GithubApiKey; 
            
            NugetDirectory.GlobFiles("*.nupkg")
                .ForEach(x =>
                {
                    DotNetNuGetPush(s => s
                        .SetTargetPath(x)
                        .EnableSkipDuplicate()
                        .SetSource(NugetApiUrl)
                        .SetApiKey(apiKey)
                    );
                });
        });
}