using FluentAssertions;
using NUnit.Framework;
using System.Threading.Tasks;

namespace DICOMClient.Tests
{
    [TestFixture]
    public class ClientConnectionTests
    {
        const string HOST = "sss.xtrabytes.services";
        const int PORT = 8443;

        [Test]
        public async Task ConnectTest()
        {
            var client = new DICOM.Client(HOST, PORT);

            var result = await client.Connect();

            result.Should().NotBeNull();
        }
    }
}
