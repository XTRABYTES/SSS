using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using DICOMClient.Cryptography;

namespace DICOMClient.DICOM
{
    public class Client
    {
        public const string VERSION = "1.0";
        public const string HASHING_ALGORITHM = "SHA256";

        private string Endpoint { get; set; }
        private static HttpClient WebClient { get; set; }
        private string Version { get; set; }
        private string PrivateKey { get; set; }
        private string PublicKey { get; set; }
        private string ServerPublicKey { get; set; }
        private string SessionId { get; set; }

        public Client (string host, int port, string version = VERSION)
        {
            Version = version;
            Endpoint = string.Format("https://{0}:{1}/v{2}/dicom", host, port, version);

            using (var rsaProvider = new RSACryptoServiceProvider(1024))
            {
                try
                {
                    // TODO Change signature verification to imitate or implement OpenSSL
                    PublicKey = rsaProvider.Decode(false);
                    PrivateKey = rsaProvider.Decode(true);
                }
                finally
                {
                    rsaProvider.PersistKeyInCsp = false;
                }
            }

            var httpClientHandler = new HttpClientHandler();
            httpClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => { return true; };
            WebClient = new HttpClient(httpClientHandler);
            WebClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        public async Task<string> Connect()
        {
            return await Execute(new Dictionary<string, object>() {
                { "method", "connect" },
                { "pubkey", PublicKey },
            });
        }

        public async Task<string> Ping()
        {
            return await Execute(new Dictionary<string, object>() {
                { "method", "ping" }
            });
        }

        public async Task<string> Echo(string message)
        {
            return await Execute(new Dictionary<string, object>() {
                { "method", "echo" },
                { "params", "message" }
            });
        }

        public async Task<string> CheckUsername(string username)
        {
            return await Execute(new Dictionary<string, object>() {
                { "method", "CheckUsername" },
                { "username", username }
            });
        }

        public async Task<string> CreateUser(string username, string password)
        {
            return await Execute(new Dictionary<string, object>() {
                { "method", "CreateUser" },
                { "username", username },
                { "username", password }
            });
        }

        public async Task<string> CheckUser(string username, string password)
        {
            return await Execute(new Dictionary<string, object>() {
                { "method", "CheckUser" },
                { "username", username },
                { "username", password }
            });
        }

        private async Task<string> Execute(Dictionary<string, object> parameters)
        {
            if (!string.IsNullOrWhiteSpace(SessionId))
            {
                parameters["session_id"] = SessionId;
            }

            var payload = JsonConvert.SerializeObject(parameters);
            // TODO Sign the payload.
            var pemSignature = string.Empty;

            var request = new Dictionary<string, object>()
            {
                { "dicom", Version },
                { "payload", payload },
                { "signature", pemSignature },
                { "pubkey", PublicKey }
            };

            var data = JsonConvert.SerializeObject(request);

            var content = new StringContent(data, Encoding.UTF8, "application/json");
            var result = await WebClient.PostAsync(Endpoint, content);

            var responseData = (JObject)JsonConvert.DeserializeObject(result.Content.ToString());
            VerifySignature(responseData);

            return responseData["payload"].Value<string>();
        }

        private bool VerifySignature(JObject data)
        {
            // TODO Ensure fields exist

            var payload = (JObject)JsonConvert.DeserializeObject(data["payload"].Value<string>());
            var signature = data["signature"].Value<string>();

            if (payload["method"].Value<string>() == "connect")
            {
                ServerPublicKey = payload["pubkey"].Value<string>();
                SessionId = payload["session_id"].Value<string>();
            }

            using (var rsaProvider = new RSACryptoServiceProvider(1024))
            {
                try
                {
                    // TODO Change signature verification to imitate or implement OpenSSL
                    var isValid = (rsaProvider.VerifyHash(Convert.FromBase64String(payload.Value<string>()), HASHING_ALGORITHM, Convert.FromBase64String(signature)));
                    return isValid;
                }
                finally
                {
                    rsaProvider.PersistKeyInCsp = false;
                }
            }
        }
    }
}
