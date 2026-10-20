using Hawk.Parsers;
using Xunit;

namespace Hawk.Core.Tests;

public class ParserHelperTests
{
    [Theory]
    [InlineData("Archive-Security-2026-05-01-12-00-00-123", "Security")]
    [InlineData("Archive-Security-2026-05-01-12-00-00", "Security")]
    [InlineData("Archive-Microsoft-Windows-PowerShell/Operational-2026-05-01-12-00-00-123", "Microsoft-Windows-PowerShell/Operational")]
    [InlineData("Security", "Security")]
    [InlineData("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon/Operational")]
    public void Archived_evtx_maps_back_to_its_base_channel(string fileChannel, string expected) =>
        Assert.Equal(expected, EvtxParser.ArchiveBaseChannel(fileChannel));
}
