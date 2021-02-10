// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Microsoft.DotNet.Docker.Tests
{
    [Trait("Category", "monitor")]
    public class MonitorImageTests
    {
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
            const string MonitorDockerArgs = "-p 52325";

            return VerifyAsync(imageData, async containerData =>
            {
                DockerHelper.Run(
                    image: containerData.ImageName,
                    name: containerData.ContainerName,
                    detach: true,
                    optionalRunArgs: MonitorDockerArgs);

                if (!Config.IsHttpVerificationDisabled)
                {
                    // Verify metrics endpoint is accessible
                    await ImageScenarioVerifier.VerifyHttpResponseFromContainerAsync(
                        containerData.ContainerName,
                        DockerHelper,
                        OutputHelper,
                        52325,
                        "metrics");
                }
            });
        }

        [LinuxImageTheory]
        [MemberData(nameof(GetImageData))]
        public Task VerifyProcessesEndpoint(MonitorImageData imageData)
        {
            const string MonitorDockerArgs =
                // Expose the 52323 port
                "-p 52323 " +
                // Disable metrics to make sure dotnet-monitor still runs without it.
                "-e DotnetMonitor_Metrics__Enabled=false " +
                // The default address is 'http://localhost:52323' which will not bind
                // in many cases for Docker since using bridge networking is very common.
                // Use wildcard binding instead.
                "-e DotnetMonitor_Urls=http://*:52323 ";

            return VerifyAsync(imageData, async containerData =>
            {
                DockerHelper.Run(
                    image: containerData.ImageName,
                    name: containerData.ContainerName,
                    detach: true,
                    optionalRunArgs: MonitorDockerArgs);

                if (!Config.IsHttpVerificationDisabled)
                {
                    // Verify metrics endpoint is accessible
                    using HttpResponseMessage responseMessage =
                        await ImageScenarioVerifier.VerifyHttpResponseFromContainerAsync(
                            containerData.ContainerName,
                            DockerHelper,
                            OutputHelper,
                            52323,
                            "processes",
                            disposeResult: false);

                    JsonDocument document = JsonDocument.Parse(responseMessage.Content.ReadAsStream());
                    JsonElement rootElement = document.RootElement;

                    // Verify returns an empty array (should not detect any processes)
                    Assert.Equal(JsonValueKind.Array, rootElement.ValueKind);
                    Assert.Equal(0, rootElement.GetArrayLength());
                }
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
                async (monitorData, sampleData, tmpVolumeName, _) =>
                {
                    string monitorDockerArgs =
                        "-p 52323 " +
                        "-e DotnetMonitor_Urls=http://*:52323 " +
                        $"-v {tmpVolumeName}:/tmp";
                    string sampleDockerArgs =
                        "-p 80 " +
                        $"-v {tmpVolumeName}:/tmp";

                    DockerHelper.Run(
                        image: sampleData.ImageName,
                        name: sampleData.ContainerName,
                        detach: true,
                        optionalRunArgs: sampleDockerArgs);

                    DockerHelper.Run(
                        image: monitorData.ImageName,
                        name: monitorData.ContainerName,
                        detach: true,
                        optionalRunArgs: monitorDockerArgs);

                    if (!Config.IsHttpVerificationDisabled)
                    {
                        using HttpResponseMessage responseMessage =
                            await ImageScenarioVerifier.VerifyHttpResponseFromContainerAsync(
                                monitorData.ContainerName,
                                DockerHelper,
                                OutputHelper,
                                52323,
                                "processes",
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
            Func<ContainerData, Task> verifyImageAsync)
        {
            ContainerData containerData = ContainerData.FromImageData(DockerHelper, imageData);
            try
            {
                await verifyImageAsync(containerData);
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
            Func<ContainerData, ContainerData, string, string, Task> verifyImageAsync)
        {
            ContainerData monitorContainerData = ContainerData.FromImageData(DockerHelper, imageData);

            SampleImageData sampleImageData = GetCorrespondingSample(imageData);
            ContainerData sampleContainerData = ContainerData.FromImageData(DockerHelper, sampleImageData);

            string tmpVolumeName = null;
            if (shareTmpVolume)
            {
                tmpVolumeName = DockerHelper.CreateVolume("tmpvol");
            }
            string diagPortVolumeName = null;
            if (shareDiagPortVolume)
            {
                diagPortVolumeName = DockerHelper.CreateVolume("diagportvol");
            }

            try
            {
                await verifyImageAsync(monitorContainerData, sampleContainerData, tmpVolumeName, diagPortVolumeName);
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
}
