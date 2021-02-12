// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
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

        internal const string EnvVar_DiagnosticPort_ConnectionMode = "DotnetMonitor_DiagnosticPort__ConnectionMode";
        internal const string EnvVar_DiagnosticPort_EndpointName = "DotnetMonitor_DiagnosticPort__EndpointName";
        internal const string EnvVar_DiagnosticPorts = "DOTNET_DiagnosticPorts";
        internal const string EnvVar_Metrics_Enabled = "DotnetMonitor_Metrics__Enabled";
        internal const string EnvVar_Urls = "DotnetMonitor_Urls";

        private const string UrlPath_Processes = "processes";
        private const string UrlPath_Metrics = "metrics";

        private const string Directory_Diag = "/diag";
        private const string Directory_Tmp = "/tmp";

        private const string File_DiagPort = Directory_Diag + "/port";

        public MonitorImageTests(ITestOutputHelper outputHelper)
        {
            OutputHelper = outputHelper;
            DockerHelper = new DockerHelper(outputHelper);
        }

        protected DockerHelper DockerHelper { get; }

        protected ITestOutputHelper OutputHelper { get; }

        public static IEnumerable<object[]> GetImageData()
        {
            return TestData.GetMonitorImageData()
                .Select(imageData => new object[] { imageData });
        }

        [LinuxImageTheory]
        [MemberData(nameof(GetImageData))]
        public void VerifyEnvironmentVariables(MonitorImageData imageData)
        {
            List<EnvironmentVariableInfo> variables = new List<EnvironmentVariableInfo>();
            variables.AddRange(ProductImageTests.GetCommonEnvironmentVariables());

            // ASPNETCORE_URLS has been unset to allow the default URL binding to occur.
            variables.Add(new EnvironmentVariableInfo("ASPNETCORE_URLS", string.Empty));
            // Diagnostics should be disabled
            variables.Add(new EnvironmentVariableInfo("COMPlus_EnableDiagnostics", "0"));

            EnvironmentVariableInfo.Validate(
                variables,
                imageData.GetImage(DockerHelper),
                imageData,
                DockerHelper);
        }

        [LinuxImageTheory]
        [MemberData(nameof(GetImageData))]
        public Task VerifyMetricsEndpoint(MonitorImageData imageData)
        {
            return VerifyAsync(
                imageData,
                async containerName =>
                {
                    if (!Config.IsHttpVerificationDisabled)
                    {
                        // Verify metrics endpoint is accessible
                        await ImageScenarioVerifier.VerifyHttpResponseFromContainerAsync(
                            containerName,
                            DockerHelper,
                            OutputHelper,
                            DefaultMetricsPort,
                            UrlPath_Metrics);
                    }
                },
                builder =>
                {
                    builder.ExposePort(DefaultMetricsPort);
                });
        }

        [LinuxImageTheory]
        [MemberData(nameof(GetImageData))]
        public Task VerifyProcessesEndpoint(MonitorImageData imageData)
        {
            return VerifyAsync(
                imageData,
                async containerName =>
                {
                    if (!Config.IsHttpVerificationDisabled)
                    {
                        // Verify metrics endpoint is accessible
                        using HttpResponseMessage responseMessage =
                            await ImageScenarioVerifier.VerifyHttpResponseFromContainerAsync(
                                containerName,
                                DockerHelper,
                                OutputHelper,
                                DefaultArtifactsPort,
                                UrlPath_Processes,
                                disposeResult: false);

                        JsonDocument document = JsonDocument.Parse(responseMessage.Content.ReadAsStream());
                        JsonElement rootElement = document.RootElement;

                        // Verify returns an empty array (should not detect any processes)
                        Assert.Equal(JsonValueKind.Array, rootElement.ValueKind);
                        Assert.Equal(0, rootElement.GetArrayLength());
                    }
                },
                builder =>
                {
                    builder.HttpUrls(DefaultArtifactsPort).DisableMetrics();
                });
        }

        [LinuxImageTheory]
        [MemberData(nameof(GetImageData))]
        public Task VerifyConnectMode(MonitorImageData imageData)
        {
            SampleImageData sampleData = GetCorrespondingSample(imageData);

            return VerifyAsync(
                imageData: imageData,
                shareTmpVolume: true,
                shareDiagPortVolume: false,
                async (monitorName, sampleName) =>
                {
                    if (!Config.IsHttpVerificationDisabled)
                    {
                        using HttpResponseMessage responseMessage =
                            await ImageScenarioVerifier.VerifyHttpResponseFromContainerAsync(
                                monitorName,
                                DockerHelper,
                                OutputHelper,
                                DefaultArtifactsPort,
                                UrlPath_Processes,
                                disposeResult: false);

                        JsonDocument document = JsonDocument.Parse(responseMessage.Content.ReadAsStream());
                        JsonElement rootElement = document.RootElement;

                        // Verify returns an array with one element (the sample container process)
                        Assert.Equal(JsonValueKind.Array, rootElement.ValueKind);
                        Assert.Equal(1, rootElement.GetArrayLength());
                    }
                });
        }

        [LinuxImageTheory]
        [MemberData(nameof(GetImageData))]
        public Task VerifyListenMode(MonitorImageData imageData)
        {
            SampleImageData sampleData = GetCorrespondingSample(imageData);

            return VerifyAsync(
                imageData: imageData,
                shareTmpVolume: false,
                shareDiagPortVolume: true,
                async (monitorName, sampleName) =>
                {
                    if (!Config.IsHttpVerificationDisabled)
                    {
                        using HttpResponseMessage responseMessage =
                            await ImageScenarioVerifier.VerifyHttpResponseFromContainerAsync(
                                monitorName,
                                DockerHelper,
                                OutputHelper,
                                DefaultArtifactsPort,
                                UrlPath_Processes,
                                disposeResult: false);

                        JsonDocument document = JsonDocument.Parse(responseMessage.Content.ReadAsStream());
                        JsonElement rootElement = document.RootElement;

                        // Verify returns an array with one element (the sample container process)
                        Assert.Equal(JsonValueKind.Array, rootElement.ValueKind);
                        Assert.Equal(1, rootElement.GetArrayLength());
                    }
                });
        }

        private async Task VerifyAsync(
            MonitorImageData imageData,
            Func<string, Task> verifyImageAsync,
            Action<DockerRunArgsBuilder> monitorArgsCallback = null)
        {
            ContainerData containerData = ContainerData.FromImageData(DockerHelper, imageData);
            try
            {
                DockerRunArgsBuilder monitorArgsBuilder = DockerRunArgsBuilder.Create();

                if (null != monitorArgsCallback)
                {
                    monitorArgsCallback(monitorArgsBuilder);
                }

                DockerHelper.Run(
                    image: containerData.ImageName,
                    name: containerData.ContainerName,
                    detach: true,
                    optionalRunArgs: monitorArgsBuilder.Build());

                await verifyImageAsync(containerData.ContainerName);
            }
            finally
            {
                DockerHelper.DeleteContainer(containerData.ContainerName);
            }
        }

        private async Task VerifyAsync(
            MonitorImageData imageData,
            bool shareTmpVolume,
            bool shareDiagPortVolume,
            Func<string, string, Task> verifyImageAsync,
            Action<DockerRunArgsBuilder> monitorArgsCallback = null,
            Action<DockerRunArgsBuilder> sampleArgsCallback = null)
        {
            ContainerData monitorContainerData = ContainerData.FromImageData(DockerHelper, imageData);

            SampleImageData sampleImageData = GetCorrespondingSample(imageData);
            ContainerData sampleContainerData = ContainerData.FromImageData(DockerHelper, sampleImageData);

            DockerRunArgsBuilder monitorArgsBuilder = DockerRunArgsBuilder.Create()
                .HttpUrls(DefaultArtifactsPort);

            DockerRunArgsBuilder sampleArgsBuilder = DockerRunArgsBuilder.Create()
                .ExposePort(DefaultHttpPort);

            string diagPortVolumeName = null;
            string tmpVolumeName = null;

            try
            {
                if (shareTmpVolume)
                {
                    tmpVolumeName = DockerHelper.CreateVolume(UniqueName("tmpvol"));

                    monitorArgsBuilder.VolumeMount(tmpVolumeName, Directory_Tmp);

                    sampleArgsBuilder.VolumeMount(tmpVolumeName, Directory_Tmp);
                }

                if (shareDiagPortVolume)
                {
                    diagPortVolumeName = DockerHelper.CreateVolume(UniqueName("diagportvol"));

                    monitorArgsBuilder.VolumeMount(diagPortVolumeName, Directory_Diag);
                    monitorArgsBuilder.DiagPortListen(File_DiagPort);

                    sampleArgsBuilder.VolumeMount(diagPortVolumeName, Directory_Diag);
                    sampleArgsBuilder.DiagPortSuspend(File_DiagPort);
                }

                if (null != monitorArgsCallback)
                {
                    monitorArgsCallback(monitorArgsBuilder);
                }

                if (null != sampleArgsCallback)
                {
                    sampleArgsCallback(sampleArgsBuilder);
                }

                DockerHelper.Run(
                    image: sampleContainerData.ImageName,
                    name: sampleContainerData.ContainerName,
                    detach: true,
                    optionalRunArgs: sampleArgsBuilder.Build());

                DockerHelper.Run(
                    image: monitorContainerData.ImageName,
                    name: monitorContainerData.ContainerName,
                    detach: true,
                    optionalRunArgs: monitorArgsBuilder.Build());

                await verifyImageAsync(
                    monitorContainerData.ContainerName,
                    sampleContainerData.ContainerName);
            }
            finally
            {
                DockerHelper.DeleteContainer(monitorContainerData.ContainerName);

                DockerHelper.DeleteContainer(sampleContainerData.ContainerName);

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

        private static string UniqueName(string name)
        {
            return $"{name}-{DateTime.Now.ToFileTime()}";
        }

        private static SampleImageData GetCorrespondingSample(MonitorImageData imageData)
        {
            return TestData.GetSampleImageData()
                .Where(d => d.IsPublished == true)
                .Where(d => d.Arch == imageData.Arch)
                .First();
        }

        private class ContainerData
        {
            public readonly string ImageName;

            public readonly string ContainerName;

            private ContainerData(string image, string name)
            {
                ImageName = image;
                ContainerName = name;
            }

            public static ContainerData FromImageData(DockerHelper dockerHelper, MonitorImageData imageData)
            {
                string image = imageData.GetImage(dockerHelper);

                string containerName = imageData.GetIdentifier("monitortest");

                return new ContainerData(image, containerName);
            }

            public static ContainerData FromImageData(DockerHelper dockerHelper, SampleImageData imageData)
            {
                string image = imageData.GetImage(SampleImageType.Aspnetapp, dockerHelper);

                string containerName = imageData.GetIdentifier("monitortest-sample");

                return new ContainerData(image, containerName);
            }
        }
    }

    internal static class MonitorDockerRunArgsBuilderExtensions
    {
        public static DockerRunArgsBuilder DisableMetrics(this DockerRunArgsBuilder builder)
        {
            return builder.EnvironmentVariable(
                MonitorImageTests.EnvVar_Metrics_Enabled,
                "false");
        }

        public static DockerRunArgsBuilder HttpUrls(this DockerRunArgsBuilder builder, params int[] ports)
        {
            IList<string> urls = new List<string>();

            foreach (int port in ports)
            {
                builder.ExposePort(port);

                urls.Add(WildcardHttpUrl(port));
            }

            return builder.EnvironmentVariable(MonitorImageTests.EnvVar_Urls, string.Join(';', urls));
        }

        public static DockerRunArgsBuilder DiagPortSuspend(this DockerRunArgsBuilder builder, string endpointName)
        {
            return builder.EnvironmentVariable(MonitorImageTests.EnvVar_DiagnosticPorts, $"{endpointName},suspend");
        }

        public static DockerRunArgsBuilder DiagPortListen(this DockerRunArgsBuilder builder, string endpointName)
        {
            return builder
                .EnvironmentVariable(MonitorImageTests.EnvVar_DiagnosticPort_ConnectionMode, "Listen")
                .EnvironmentVariable(MonitorImageTests.EnvVar_DiagnosticPort_EndpointName, endpointName);
        }

        private static string WildcardHttpUrl(int port)
        {
            return $"http://*:{port}";
        }
    }
}
