// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//

using System.Globalization;
using System.Text;

namespace Microsoft.DotNet.Docker.Tests
{
    internal class DockerRunArgsBuilder
    {
        private readonly StringBuilder _builder =
                new StringBuilder();

        private DockerRunArgsBuilder()
        {
        }

        public static DockerRunArgsBuilder Create()
        {
            return new DockerRunArgsBuilder();
        }

        public string Build()
        {
            return _builder.ToString();
        }

        public DockerRunArgsBuilder EnvironmentVariable(string name, string value)
        {
            _builder.AppendFormat(CultureInfo.InvariantCulture, "-e {0}={1} ", name, value);
            return this;
        }

        public DockerRunArgsBuilder ExposePort(int port)
        {
            _builder.AppendFormat(CultureInfo.InvariantCulture, "-p {0} ", port);
            return this;
        }

        public DockerRunArgsBuilder VolumeMount(string name, string path)
        {
            _builder.AppendFormat(CultureInfo.InvariantCulture, "-v {0}:{1} ", name, path);
            return this;
        }
    }
}
