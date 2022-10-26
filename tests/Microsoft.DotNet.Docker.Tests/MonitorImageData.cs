﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;

namespace Microsoft.DotNet.Docker.Tests
{
    public class MonitorImageData : VersionedImageData
    {
        private Version _runtimeVersion;

        public override Version RuntimeVersion
        {
            get => _runtimeVersion;
            set => _runtimeVersion = value;
        }

        public string OSTag { get; set; }

        public string Tag => GetTagName(VersionString, OSTag);

        public string GetImage(DockerHelper dockerHelper)
        {
            string imageName = GetImageName(Tag, "monitor");

            PullImageIfNecessary(imageName, dockerHelper);

            return imageName;
        }
    }
}
