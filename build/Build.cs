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

	[Solution] readonly Solution Solution;
	[GitRepository] readonly GitRepository GitRepository;
	[GitVersion] readonly GitVersion GitVersion;

	[Parameter] string NugetApiUrl = "https://api.nuget.org/v3/index.json";
	[Parameter] string NugetApiKey;

	public static int Main() => Execute<Build>(x => x.Compile);

	[Parameter("Configuration to build - Default is 'Debug' (local) or 'Release' (server)")]
	readonly Configuration Configuration = IsLocalBuild ? Configuration.Debug : Configuration.Release;

	AbsolutePath SourceDirectory => RootDirectory / "src";
	AbsolutePath TestsDirectory => RootDirectory / "tests";
	AbsolutePath AnalyzerDirectory => RootDirectory / "analyzers";
	AbsolutePath ArtifactsDirectory => RootDirectory / "artifacts";
	AbsolutePath NugetDirectory => ArtifactsDirectory / "nuget";

	Target Clean => _ => _
		.Before(Restore)
		.Executes(() =>
		{

		});

	Target Restore => _ => _
		.Executes(() =>
		{
			DotNetRestore(_ => _
			   .SetProjectFile(Solution));
		});

	Target Compile => _ => _
		.DependsOn(Restore)
		.Executes(() =>
		{
			Console.WriteLine($"Solution: {Solution}");
			Console.WriteLine($"GitVersion: {GitVersion}");

			DotNetBuild(_ => _
			   .SetProjectFile(Solution)
			   .SetConfiguration(Configuration)
			   .SetAssemblyVersion(GitVersion.AssemblySemVer)
			   .SetFileVersion(GitVersion.AssemblySemFileVer)
			   .SetInformationalVersion(GitVersion.InformationalVersion)
			   .EnableNoRestore());
		});

	Target Pack => _ => _
	  .DependsOn(Compile)
	  .Executes(() =>
	  {
		  int commitNum = 0;
		  string NuGetVersionCustom = GitVersion.NuGetVersionV2;

		  //if it's not a tagged release - append the commit number to the package version
		  //tagged commits on master have versions
		  // - v0.3.0-beta
		  //other commits have
		  // - v0.3.0-beta1

		  if (Int32.TryParse(GitVersion.CommitsSinceVersionSource, out commitNum))
			  NuGetVersionCustom = commitNum > 0 ? NuGetVersionCustom + $"{commitNum}" : NuGetVersionCustom;


		  DotNetPack(s => s
				.SetProject(Solution.GetProject("QuickProxyNet"))
				.SetConfiguration(Configuration)
				.EnableNoBuild()
				.EnableNoRestore()
				.SetVersion(NuGetVersionCustom)
				//.SetDescription("EFcore based Outbox for Eventfully")
				//.SetPackageTags("messaging servicebus cqrs distributed azureservicebus efcore ddd microservice outbox")
				.SetNoDependencies(true)
				.SetOutputDirectory(ArtifactsDirectory / "nuget"));

	  });

	Target Push => _ => _
	  .DependsOn(Pack)
	  .Requires(() => NugetApiUrl)
	  .Requires(() => NugetApiKey)
	  .Requires(() => Configuration.Equals(Configuration.Release))
	  .Executes(() =>
	  {
		  NugetDirectory.GlobFiles("*.nupkg")
				  .NotEmpty()
				  // .Where(x => !x.EndsWith("symbols.nupkg"))
				  .ForEach(x =>
				  {
					  
					  DotNetNuGetPush(s => s
						  .SetTargetPath(x)
						  .SetSource(NugetApiUrl)
						  .SetApiKey(NugetApiKey)
					  );
				  });
	  });

}
