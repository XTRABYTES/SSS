using FluentAssertions;
using Newtonsoft.Json;
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
        public async Task ConnectReturnsDataTest()
        {
            var client = new DICOM.Client(HOST, PORT);

            var result = await client.Connect();

            result.Should().NotBeNullOrWhiteSpace();
        }

        [Test]
        public async Task ConnectReturnsValidDataTest()
        {
            var client = new DICOM.Client(HOST, PORT);

            var result = await client.Connect();

            dynamic data = JsonConvert.DeserializeObject(result);

            string method = data.method;
            string sessionId = data.session_id;
            string publicKey = data.pubkey;

            method.Should().Be("connect");
            sessionId.Should().NotBeNullOrWhiteSpace();
            publicKey.Should().Contain("BEGIN PUBLIC KEY").And.Contain("END PUBLIC KEY");
        }
    }
}
