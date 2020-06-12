#!/usr/bin/env bash

# Stop script on NZEC
set -e
# Stop script if unbound variable found (use ${var:-} if intentional)
set -u

channel=$1
monitorChannel=$2

curl -SLo sdk.zip https://aka.ms/dotnet/$channel/Sdk/dotnet-sdk-win-x64.zip
unzip sdk.zip -d sdk
rm sdk.zip

sdkVersionsPath=$(find sdk/sdk -name .version)
sdkVer=$(cat $sdkVersionsPath | head -2 | tail -1)

runtimeVersionsPath=$(find sdk/shared/Microsoft.NETCore.App -name .version)
runtimeVer=$(cat $runtimeVersionsPath | tail -1)

aspnetVersionsPath=$(find sdk/shared/Microsoft.AspNetCore.App -name Microsoft.AspNetCore.App.versions.txt)
aspnetVer=$(cat $aspnetVersionsPath | tail -1)

rm -rf sdk

curl -SLo dotnet-monitor.nupkg https://aka.ms/dotnet/$monitorChannel/diagnostics/monitor5.0/dotnet-monitor.nupkg
unzip dotnet-monitor.nupkg -d dotnet-monitor
rm dotnet-monitor.nupkg

monitorVersionPath=$(find dotnet-monitor -name dotnet-monitor.nuspec)
# In nuspec, there is only one element named "version" and it is the version of the nupkg.
# All other uses of "version" are attributes on other elements. grep using Perl regex, reporting
# the first match, and only printing what was matched.
monitorVer=$(cat $monitorVersionPath | grep -oPm1 "(?<=<version>)[^<]+")

rm -rf dotnet-monitor

echo "##vso[task.setvariable variable=sdkVer]$sdkVer"
echo "##vso[task.setvariable variable=runtimeVer]$runtimeVer"
echo "##vso[task.setvariable variable=aspnetVer]$aspnetVer"
echo "##vso[task.setvariable variable=monitorVer]$monitorVer"
