// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Microsoft.DotNet.Docker.Tests
{
    [Trait("Category", "monitor")]
    public class MonitorImageTests
    {
        private const int DefaultHttpPort = 80;
        private const int DefaultArtifactsPort = 52323;
        private const int DefaultMetricsPort = 52325;

        private const string UrlPath_Processes = "processes";
        private const string UrlPath_Metrics = "metrics";

        private const string Directory_Certificates = "/certs";
        private const string Directory_Diag = "/diag";
        private const string Directory_Tmp = "/tmp";

        private const string File_DiagPort = Directory_Diag + "/port";
        private const string File_HttpsCerticate = Directory_Certificates + "/cert.pfx";

        /// <summary>
        /// Command line switch to disable authentication. By default,
        /// dotnet-monitor requires authentication on the artifacts port.
        /// </summary>
        private const string Switch_NoAuthentication = "--no-auth";

        public MonitorImageTests(ITestOutputHelper outputHelper)
        {
            OutputHelper = outputHelper;
            DockerHelper = new DockerHelper(outputHelper);
        }

        protected DockerHelper DockerHelper { get; }

        protected ITestOutputHelper OutputHelper { get; }

        /// <summary>
        /// Get the SDK image that has the same arch, runtime version, and appropriate OS as the .NET Monitor image.
        /// </summary>
        private static ProductImageData GetCorrespondingSdkImage(MonitorImageData monitorImageData)
        {
            ProductImageData sdkImage = TestData.GetAllImageData()
                .FilterImagesByArch()
                .FilterImagesByOs(OS.GetDistrofulOs(monitorImageData.OS))
                .FilterImagesByRuntimeVersion(monitorImageData.RuntimeVersion)
                .FilterToSdkImages()
                .FirstOrDefault();

            if (null == sdkImage)
            {
                throw new InvalidOperationException($"Unable to find corresponding SDK image for .NET Monitor {monitorImageData.Tag}");
            }

            return sdkImage;
        }

        /// <summary>
        /// Gets each dotnet-monitor image.
        /// </summary>
        public static IEnumerable<object[]> GetMonitorData()
        {
            IList<object[]> data = new List<object[]>();
            foreach (MonitorImageData monitorImageData in TestData.GetMonitorImageData())
            {
                data.Add(new object[] { monitorImageData });
            }
            return data;
        }

        /// <summary>
        /// Gets each dotnet-monitor image paired with a corresponding SDK image.
        /// </summary>
        public static IEnumerable<object[]> GetMonitorSdkData()
        {
            IList<object[]> data = new List<object[]>();
            foreach (MonitorImageData monitorImageData in TestData.GetMonitorImageData())
            {
                data.Add(new object[] { monitorImageData, GetCorrespondingSdkImage(monitorImageData) });
            }
            return data;
        }

        /// <summary>
        /// Gets each dotnet-monitor image paired with each sample aspnetcore image of the same architecture
        /// and a corresponding SDK image. Allows for testing volume mounts and diagnostic port usage among different distros.
        /// </summary>
        private static IEnumerable<object[]> GetMonitorSdkSampleData(bool isConnectMode)
        {
            IList<object[]> data = new List<object[]>();
            foreach (MonitorImageData monitorImageData in TestData.GetMonitorImageData())
            {
                foreach (SampleImageData sampleImageData in TestData.GetAllSampleImageData())
                {
                    // Only use published images (do not want to build unpublished images in the tests)
                    if (!sampleImageData.IsPublished)
                        continue;

                    // Only consider the sample image if it has the same architecture.
                    if (monitorImageData.Arch != sampleImageData.Arch)
                        continue;

                    if (isConnectMode)
                    {
                        // The dotnet-monitor process is only able to connect to the other container process' diagnostic port
                        // if it is running as the same user or is running as root. If the target application container is
                        // running as root, then the dotnet-monitor must be running as root, which is not the case for distroless.
                        if (monitorImageData.IsDistroless && !sampleImageData.IsDistroless)
                            continue;
                    }
                    else
                    {
                        // In listen mode, if the dotnet-monitor container is non-distroless, then it has a communication
                        // pipe that is established as root. This requires that the target application container to be running
                        // as root in order for it to connect to the pipe. If dotnet-monitor is distroless, then either
                        // distroless (as long as it is the same user) or non-distroless will be able to communicate with it.
                        if (!monitorImageData.IsDistroless && sampleImageData.IsDistroless)
                            continue;
                    }

                    data.Add(new object[] { monitorImageData, GetCorrespondingSdkImage(monitorImageData), sampleImageData });
                }
            }
            return data;
        }

        public static IEnumerable<object[]> GetConnectModeScenarioData()
        {
            return GetMonitorSdkSampleData(isConnectMode: true);
        }

        public static IEnumerable<object[]> GetListenModeScenarioData()
        {
            return GetMonitorSdkSampleData(isConnectMode: false);
        }

        /// <summary>
        /// Verifies that the environment variables essential to dotnet-monitor are set correctly.
        /// </summary>
        [LinuxImageTheory]
        [MemberData(nameof(GetMonitorData))]
        public void VerifyEnvironmentVariables(MonitorImageData monitorImageData)
        {
            List<EnvironmentVariableInfo> variables = new List<EnvironmentVariableInfo>();
            variables.AddRange(ProductImageTests.GetCommonEnvironmentVariables());

            // ASPNETCORE_URLS has been unset to allow the default URL binding to occur.
            variables.Add(new EnvironmentVariableInfo("ASPNETCORE_URLS", string.Empty));
            // Diagnostics should be disabled
            variables.Add(new EnvironmentVariableInfo("COMPlus_EnableDiagnostics", "0"));
            // DefaultProcess filter should select a process with a process ID of 1
            variables.Add(new EnvironmentVariableInfo("DefaultProcess__Filters__0__Key", "ProcessId"));
            variables.Add(new EnvironmentVariableInfo("DefaultProcess__Filters__0__Value", "1"));
            // Existing (orphaned) diagnostic port should be delete before starting server
            variables.Add(new EnvironmentVariableInfo("DiagnosticPort__DeleteEndpointOnStartup", "true"));
            // GC mode should be set to Server
            variables.Add(new EnvironmentVariableInfo("DOTNET_gcServer", "1"));
            // Console logger format should be JSON and output UTC timestamps without timezone information
            variables.Add(new EnvironmentVariableInfo("Logging__Console__FormatterName", "json"));
            variables.Add(new EnvironmentVariableInfo("Logging__Console__FormatterOptions__TimestampFormat", "yyyy-MM-ddTHH:mm:ss.fffffffZ"));
            variables.Add(new EnvironmentVariableInfo("Logging__Console__FormatterOptions__UseUtcTimestamp", "true"));

            EnvironmentVariableInfo.Validate(
                variables,
                monitorImageData.GetImage(DockerHelper),
                monitorImageData,
                DockerHelper);
        }

        /// <summary>
        /// Tests that the image can run without additional configuration.
        /// </summary>
        [LinuxImageTheory]
        [MemberData(nameof(GetMonitorSdkData))]
        public Task VerifyMonitorDefault(MonitorImageData monitorImageData, ProductImageData sdkImageData)
        {
            return VerifyMonitorAsync(
                monitorImageData,
                sdkImageData,
                noAuthentication: false,
                noHttpsCertificate: true,
                async containerName =>
                {
                    if (!Config.IsHttpVerificationDisabled)
                    {
                        await ValidateMetricsPortAndRouteAsync(containerName);
                    }
                });
        }

        /// <summary>
        /// Tests that the image can run with https enabled, that the artifacts routes
        /// are authenticated, and the metrics endpoint is usable without
        /// providing authentication.
        /// </summary>
        [LinuxImageTheory]
        [MemberData(nameof(GetMonitorSdkData))]
        public Task VerifyMonitorHttpsWithAuth(MonitorImageData monitorImageData, ProductImageData sdkImageData)
        {
            GenerateKeyOutput output = GenerateKey(monitorImageData);
            AuthenticationHeaderValue authorizationHeader = AuthenticationHeaderValue.Parse(output.AuthorizationHeader);

            return VerifyMonitorAsync(
                monitorImageData,
                sdkImageData,
                noAuthentication: false,
                noHttpsCertificate: false,
                async containerName =>
                {
                    if (!Config.IsHttpVerificationDisabled)
                    {
                        await ValidateProcessesRouteUnauthorizedAsync(containerName, Uri.UriSchemeHttps);

                        await ValidateProcessesRouteAndCountAsync(containerName, Uri.UriSchemeHttps, processCount: 0, authorizationHeader);

                        await ValidateMetricsPortAndRouteAsync(containerName);
                    }
                },
                builder =>
                {
                    // Configure authentication
                    builder.MonitorApiKey(output.Authentication.MonitorApiKey);
                });
        }

        /// <summary>
        /// Tests that the image can run with https enabled, that the artifacts routes
        /// respond with Unauthorized (because auth was not configured), and the metrics route
        /// is usable without providing authentication.
        /// </summary>
        [LinuxImageTheory]
        [MemberData(nameof(GetMonitorSdkData))]
        public Task VerifyMonitorHttpsUnconfiguredAuth(MonitorImageData monitorImageData, ProductImageData sdkImageData)
        {
            return VerifyMonitorAsync(
                monitorImageData,
                sdkImageData,
                noAuthentication: false,
                noHttpsCertificate: false,
                async containerName =>
                {
                    if (!Config.IsHttpVerificationDisabled)
                    {
                        await ValidateProcessesRouteUnauthorizedAsync(containerName, Uri.UriSchemeHttps);

                        await ValidateMetricsPortAndRouteAsync(containerName);
                    }
                });
        }

        /// <summary>
        /// Tests that the image can run with https enabled and that the artifacts routes
        /// and metrics route are usable without providing authentication.
        /// </summary>
        [LinuxImageTheory]
        [MemberData(nameof(GetMonitorSdkData))]
        public Task VerifyMonitorHttpsNoAuth(MonitorImageData monitorImageData, ProductImageData sdkImageData)
        {
            return VerifyMonitorAsync(
                monitorImageData,
                sdkImageData,
                noAuthentication: true,
                noHttpsCertificate: false,
                async containerName =>
                {
                    if (!Config.IsHttpVerificationDisabled)
                    {
                        await ValidateProcessesRouteAndCountAsync(containerName, Uri.UriSchemeHttps, processCount: 0);

                        await ValidateMetricsPortAndRouteAsync(containerName);
                    }
                });
        }

        /// <summary>
        /// Verifies that the image can discover a dotnet process
        /// in another container via mounting the /tmp directory.
        /// </summary>
        [LinuxImageTheory]
        [MemberData(nameof(GetConnectModeScenarioData))]
        public Task VerifyConnectMode(MonitorImageData monitorImageData, ProductImageData sdkImageData, SampleImageData sampleImageData)
        {
            return VerifyMonitorWithSampleAsync(
                monitorImageData,
                sampleImageData,
                sdkImageData,
                shareTmpVolume: true,
                listenDiagPortVolume: false,
                async (monitorName, sampleName) =>
                {
                    if (!Config.IsHttpVerificationDisabled)
                    {
                        await ValidateProcessesRouteAndCountAsync(monitorName, Uri.UriSchemeHttp, processCount: 1);

                        await ValidateMetricsPortAndRouteAsync(monitorName);
                    }
                });
        }

        /// <summary>
        /// Verifies that the image can listen for dotnet processes
        /// in other containers by having them connect to the diagnostic port listener.
        /// </summary>
        [LinuxImageTheory]
        [MemberData(nameof(GetListenModeScenarioData))]
        public Task VerifyListenMode(MonitorImageData monitorImageData, ProductImageData sdkImageData, SampleImageData sampleImageData)
        {
            return VerifyMonitorWithSampleAsync(
                monitorImageData,
                sampleImageData,
                sdkImageData,
                shareTmpVolume: false,
                listenDiagPortVolume: true,
                async (monitorName, sampleName) =>
                {
                    if (!Config.IsHttpVerificationDisabled)
                    {
                        await ValidateProcessesRouteAndCountAsync(monitorName, Uri.UriSchemeHttp, processCount: 1);

                        await ValidateMetricsPortAndRouteAsync(monitorName);
                    }
                });
        }

        /// <summary>
        /// Runs a single instance of the dotnet-monitor image.
        /// </summary>
        /// <param name="imageData">The image data of the dotnet-monitor image.</param>
        /// <param name="noAuthentication">Set to true to disable dotnet-monitor authenication.</param>
        /// <param name="noHttpsCertificate">Set to true to prevent the creation and mounting of an HTTPS certificate.</param>
        /// <param name="verifyContainerAsync">Callback to test some aspect of the container.</param>
        /// <param name="runArgsCallback">Allows for modifying the "docker run" args of the container.</param>
        private async Task VerifyMonitorAsync(
            MonitorImageData imageData,
            ProductImageData sdkImageData,
            bool noAuthentication,
            bool noHttpsCertificate,
            Func<string, Task> verifyContainerAsync,
            Action<DockerRunArgsBuilder> runArgsCallback = null
            )
        {
            GetNames(imageData, out string monitorImageName, out string monitorContainerName);

            string certsVolumeName = null;
            try
            {
                DockerRunArgsBuilder builder = DockerRunArgsBuilder.Create()
                    .ExposePort(DefaultMetricsPort)
                    .ExposePort(DefaultArtifactsPort);

                if (!noHttpsCertificate)
                {
                    certsVolumeName = MountHttpsCertificate(builder, sdkImageData);
                }

                // Allow modification of the "docker run" args of the monitor container
                runArgsCallback?.Invoke(builder);

                DockerHelper.Run(
                    image: monitorImageName,
                    name: monitorContainerName,
                    command: GetMonitorDockerCommandArgs(imageData, noAuthentication),
                    optionalRunArgs: builder.Build(),
                    detach: true);

                await verifyContainerAsync(monitorContainerName);
            }
            finally
            {
                DockerHelper.DeleteContainer(monitorContainerName);

                if (!string.IsNullOrEmpty(certsVolumeName))
                {
                    DockerHelper.DeleteVolume(certsVolumeName);
                }
            }
        }

        /// <summary>
        /// Runs a single instance of each of the dotnet-monitor and samples images.
        /// </summary>
        /// <param name="monitorImageData">The image data of the dotnet-monitor image.</param>
        /// <param name="sampleImageData">The image data of the sample image.</param>
        /// <param name="sdkImageData">The image data of the SDK image used for generating an HTTPS certificate.</param>
        /// <param name="shareTmpVolume">Set to true to mount the /tmp directory in both containers.</param>
        /// <param name="listenDiagPortVolume">
        /// Set to true to have the monitor container listen with a diagnostic port listener
        /// for diagnostic connections from the samples container.
        /// </param>
        /// <param name="verifyContainerAsync">Callback to test some aspect of the containers.</param>
        private async Task VerifyMonitorWithSampleAsync(
            MonitorImageData monitorImageData,
            SampleImageData sampleImageData,
            ProductImageData sdkImageData,
            bool shareTmpVolume,
            bool listenDiagPortVolume,
            Func<string, string, Task> verifyContainerAsync)
        {
            GetNames(sampleImageData, out string sampleImageName, out string sampleContainerName);

            string diagPortVolumeName = null;
            string tmpVolumeName = null;

            try
            {
                bool allowDistrolessUserToUseVolume = monitorImageData.IsDistroless || sampleImageData.IsDistroless;

                DockerRunArgsBuilder sampleBuilder = DockerRunArgsBuilder.Create();

                // Create a volume for the two containers to share the /tmp directory.
                if (shareTmpVolume)
                {
                    tmpVolumeName = DockerHelper.CreateTmpfsVolume(UniqueVolumeName("tmp"), allowDistrolessUserToUseVolume);

                    sampleBuilder.VolumeMount(tmpVolumeName, Directory_Tmp);
                }

                // Create a volume so that the dotnet-monitor container can provide a
                // diagnostic listening port to the samples container so that the samples
                // process can connect to the dotnet-monitor process.
                if (listenDiagPortVolume)
                {
                    diagPortVolumeName = DockerHelper.CreateTmpfsVolume(UniqueVolumeName("diag"), allowDistrolessUserToUseVolume);

                    sampleBuilder.VolumeMount(diagPortVolumeName, Directory_Diag);
                    sampleBuilder.RuntimeSuspend(File_DiagPort);
                }

                DockerHelper.Run(
                    image: sampleImageName,
                    name: sampleContainerName,
                    optionalRunArgs: sampleBuilder.Build(),
                    detach: true);

                await VerifyMonitorAsync(
                    monitorImageData,
                    sdkImageData,
                    noAuthentication: true,
                    noHttpsCertificate: true,
                    monitorContainerName => verifyContainerAsync(monitorContainerName, sampleContainerName),
                    monitorBuilder =>
                    {
                        monitorBuilder.SetUrlHttpAny(DefaultArtifactsPort);

                        if (shareTmpVolume)
                        {
                            monitorBuilder.VolumeMount(tmpVolumeName, Directory_Tmp);
                        }

                        if (listenDiagPortVolume)
                        {
                            monitorBuilder.VolumeMount(diagPortVolumeName, Directory_Diag);
                            monitorBuilder.MonitorListen(File_DiagPort);
                        }
                    });
            }
            finally
            {
                DockerHelper.DeleteContainer(sampleContainerName);

                if (!string.IsNullOrEmpty(diagPortVolumeName))
                {
                    DockerHelper.DeleteVolume(diagPortVolumeName);
                }

                if (!string.IsNullOrEmpty(tmpVolumeName))
                {
                    DockerHelper.DeleteVolume(tmpVolumeName);
                }
            }
        }

        private async Task ValidateMetricsPortAndRouteAsync(string containerName)
        {
            // Verify HTTP /metrics route without authentication => 200
            using HttpResponseMessage metricsMessage =
                await ImageScenarioVerifier.GetHttpResponseFromContainerAsync(
                    containerName,
                    DockerHelper,
                    OutputHelper,
                    DefaultMetricsPort,
                    UrlPath_Metrics);

            string metricsContent = await metricsMessage.Content.ReadAsStringAsync();

            // Metrics should not return any content if
            // no processes are detected.
            Assert.Equal(string.Empty, metricsContent);
        }

        private async Task ValidateProcessesRouteAndCountAsync(string containerName, string uriScheme, int processCount, AuthenticationHeaderValue authorizationHeader = null)
        {
            using HttpResponseMessage responseMessage =
                await ImageScenarioVerifier.GetHttpResponseFromContainerAsync(
                    containerName,
                    DockerHelper,
                    OutputHelper,
                    DefaultArtifactsPort,
                    UrlPath_Processes,
                    authorizationHeader: authorizationHeader,
                    uriScheme: uriScheme);

            JsonElement rootElement = GetContentAsJsonElement(responseMessage);

            // Verify returns an array with one element (the sample container process)
            Assert.Equal(JsonValueKind.Array, rootElement.ValueKind);
            Assert.Equal(processCount, rootElement.GetArrayLength());
        }

        private async Task ValidateProcessesRouteUnauthorizedAsync(string containerName, string uriScheme)
        {
            // Verify HTTP /processes route without authentication => 401
            await ImageScenarioVerifier.VerifyHttpResponseFromContainerAsync(
                containerName,
                DockerHelper,
                OutputHelper,
                DefaultArtifactsPort,
                UrlPath_Processes,
                m => VerifyStatusCode(m, HttpStatusCode.Unauthorized),
                uriScheme);
        }

        private static string UniqueVolumeName(string name)
        {
            return $"montest-volume-{name}-{DateTime.Now.ToFileTime()}";
        }

        private static string CreateContainerPrefix(string name)
        {
            return $"montest-container-{name}";
        }

        private string GetMonitorDockerCommandArgs(MonitorImageData imageData, bool noAuthentication)
        {
            StringBuilder builtCommandline = new StringBuilder();

            // Get the default arguments for the image
            string imageCmd = DockerHelper.GetImageCmd(imageData.GetImage(DockerHelper));
            string[] defaultArgs = JsonSerializer.Deserialize<string[]>(imageCmd);
            foreach (string defaultArg in defaultArgs)
            {
                if (builtCommandline.Length > 0)
                {
                    builtCommandline.Append(' ');
                }
                builtCommandline.Append(defaultArg);
            }

            // Append additional arguments if necessary

            if (noAuthentication)
            {
                if (builtCommandline.Length > 0)
                {
                    builtCommandline.Append(' ');
                }
                builtCommandline.Append(Switch_NoAuthentication);
            }

            return builtCommandline.ToString();
        }

        private void GetNames(MonitorImageData imageData, out string imageName, out string containerName)
        {
            imageName = imageData.GetImage(DockerHelper);
            containerName = imageData.GetIdentifier(CreateContainerPrefix("monitor"));
        }

        private void GetNames(SampleImageData imageData, out string imageName, out string containerName)
        {
            // Need to allow pulling of the sample image since these are not built in the same pipeline
            // as the other images; otherwise, these tests will fail due to lack of sample image.
            imageName = imageData.GetImage(SampleImageType.Aspnetapp, DockerHelper, allowPull: true);
            containerName = imageData.GetIdentifier(CreateContainerPrefix("sample"));
        }

        private void GetNames(ProductImageData imageData, out string imageName, out string containerName)
        {
            // Need to allow pulling of the sample image since these may not be built in the same pipeline
            // if the runtime/aspnet/sdk images did not change since the last build.
            imageName = imageData.GetImage(DotNetImageType.SDK, DockerHelper);
            containerName = imageData.GetIdentifier(CreateContainerPrefix("sdk"));
        }

        private void VerifyStatusCode(HttpResponseMessage message, HttpStatusCode statusCode)
        {
            if (message.StatusCode != statusCode)
            {
                throw new HttpRequestException($"Expected status code {statusCode}", null, statusCode);
            }
        }

        private static JsonElement GetContentAsJsonElement(HttpResponseMessage message)
        {
            using (Stream stream = message.Content.ReadAsStream())
            {
                return JsonDocument.Parse(stream).RootElement;
            }
        }

        private GenerateKeyOutput GenerateKey(MonitorImageData imageData)
        {
            GetNames(imageData, out string monitorImageName, out string monitorContainerName);
            try
            {
                DockerRunArgsBuilder runArgsBuilder = DockerRunArgsBuilder.Create()
                    .Entrypoint("dotnet-monitor");

                string json = DockerHelper.Run(
                    image: monitorImageName,
                    name: monitorContainerName,
                    command: "generatekey -o machinejson",
                    optionalRunArgs: runArgsBuilder.Build());

                GenerateKeyOutput output = JsonSerializer.Deserialize<GenerateKeyOutput>(json);

                Assert.NotNull(output?.Authentication?.MonitorApiKey?.PublicKey);
                Assert.NotNull(output?.Authentication?.MonitorApiKey?.Subject);
                Assert.NotNull(output?.AuthorizationHeader);

                return output;
            }
            finally
            {
                DockerHelper.DeleteContainer(monitorContainerName);
            }
        }

        /// <summary>
        /// Creates a volume with an HTTP certificate and configures the .NET Monitor container
        /// to consume the certificate from that volume.
        /// </summary>
        /// <returns>The name of the certificate volume.</returns>
        private string MountHttpsCertificate(
            DockerRunArgsBuilder monitorArgsBuilder,
            ProductImageData sdkImageData)
        {
            string certsVolumeName = DockerHelper.CreateVolume(UniqueVolumeName("certs"));

            GetNames(sdkImageData, out string sdkImageName, out string sdkContainerName);

            string certPassword = Guid.NewGuid().ToString("N");
            try
            {
                DockerRunArgsBuilder sdkArgsBuilder = DockerRunArgsBuilder.Create()
                    .VolumeMount(certsVolumeName, Directory_Certificates)
                    .Entrypoint("dotnet");

                // Create an https certificate and save to the certificate volume
                DockerHelper.Run(
                    sdkImageName,
                    sdkContainerName,
                    command: $"dev-certs https -ep {File_HttpsCerticate} -p {certPassword}",
                    optionalRunArgs: sdkArgsBuilder.Build());
            }
            finally
            {
                DockerHelper.DeleteContainer(sdkContainerName);
            }

            // Mount the certificate volume and set ASP.NET configuration to consume it.
            monitorArgsBuilder.VolumeMount(certsVolumeName, Directory_Certificates)
                .EnvironmentVariable("ASPNETCORE_Kestrel__Certificates__Default__Password", certPassword)
                .EnvironmentVariable("ASPNETCORE_Kestrel__Certificates__Default__Path", File_HttpsCerticate);

            return certsVolumeName;
        }
    }

    internal static class MonitorDockerRunArgsBuilderExtensions
    {
        // dotnet-monitor variables
        internal const string EnvVar_Authentication_MonitorApiKey_PublicKey = "DotnetMonitor_Authentication__MonitorApiKey__PublicKey";
        internal const string EnvVar_Authentication_MonitorApiKey_Subject = "DotnetMonitor_Authentication__MonitorApiKey__Subject";
        internal const string EnvVar_DiagnosticPort_ConnectionMode = "DotnetMonitor_DiagnosticPort__ConnectionMode";
        internal const string EnvVar_DiagnosticPort_EndpointName = "DotnetMonitor_DiagnosticPort__EndpointName";
        internal const string EnvVar_Metrics_Enabled = "DotnetMonitor_Metrics__Enabled";
        internal const string EnvVar_Urls = "DotnetMonitor_Urls";

        // runtime variables
        internal const string EnvVar_DiagnosticPorts = "DOTNET_DiagnosticPorts";

        public static DockerRunArgsBuilder MonitorApiKey(this DockerRunArgsBuilder builder, MonitorApiKeyOptions options)
        {
            return builder
                .EnvironmentVariable(EnvVar_Authentication_MonitorApiKey_PublicKey, options.PublicKey)
                .EnvironmentVariable(EnvVar_Authentication_MonitorApiKey_Subject, options.Subject);
        }

        /// <summary>
        /// Disables the metrics endpoint in dotnet-monitor.
        /// </summary>
        public static DockerRunArgsBuilder MonitorDisableMetrics(this DockerRunArgsBuilder builder)
        {
            return builder.EnvironmentVariable(EnvVar_Metrics_Enabled, "false");
        }

        /// <summary>
        /// Places dotnet-monitor into listen mode, allowing dotnet processes to connect
        /// to its diagnostic port listener.
        /// </summary>
        public static DockerRunArgsBuilder MonitorListen(this DockerRunArgsBuilder builder, string endpointName)
        {
            return builder
                .EnvironmentVariable(EnvVar_DiagnosticPort_ConnectionMode, "Listen")
                .EnvironmentVariable(EnvVar_DiagnosticPort_EndpointName, endpointName);
        }

        /// <summary>
        /// Sets the artifacts url with the port
        /// </summary>
        public static DockerRunArgsBuilder SetUrlHttpAny(this DockerRunArgsBuilder builder, int port)
        {
            return builder.EnvironmentVariable(EnvVar_Urls, WildcardUrl(port));
        }

        /// <summary>
        /// Suspends a dotnet runtime until it can connect to a diagnostic port listener
        /// at the specified endpoint name.
        /// </summary>
        public static DockerRunArgsBuilder RuntimeSuspend(this DockerRunArgsBuilder builder, string endpointName)
        {
            return builder.EnvironmentVariable(EnvVar_DiagnosticPorts, $"{endpointName},suspend");
        }

        private static string WildcardUrl(int port)
        {
            return $"http://*:{port}";
        }
    }

    /// <summary>
    /// Represents the structured output of a "dotnet-monitor generatekey -o machinejson" invocation.
    /// </summary>
    internal sealed class GenerateKeyOutput
    {
        public AuthenticationOptions Authentication { get; set; }

        public string AuthorizationHeader { get; set; }
    }

    internal sealed class AuthenticationOptions
    {
        public MonitorApiKeyOptions MonitorApiKey { get; set; }
    }

    internal sealed class MonitorApiKeyOptions
    {
        public string PublicKey { get; set; }

        public string Subject { get; set; }
    }
}
