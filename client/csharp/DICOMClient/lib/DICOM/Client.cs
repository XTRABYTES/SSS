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
                    PrivateKey = RSAKeyUtilities.ExportPrivateKey(rsaProvider);
                    PublicKey = RSAKeyUtilities.ExportPublicKey(rsaProvider);
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
            Console.WriteLine("Sending request to SSS...");

            if (!string.IsNullOrWhiteSpace(SessionId))
            {
                parameters["session_id"] = SessionId;
            }

            var payload = JsonConvert.SerializeObject(parameters);
            var pemSignature = RSAKeyUtilities.SignData(payload, PrivateKey);

            var request = new Dictionary<string, object>()
            {
                { "dicom", Version },
                { "payload", payload },
                { "signature", pemSignature },
                { "pubkey", PublicKey }
            };

            var data = JsonConvert.SerializeObject(request);

            var content = new StringContent(data, Encoding.UTF8, "application/json");
            var postResult = await WebClient.PostAsync(Endpoint, content);
            var result = string.Empty;

            if (postResult.IsSuccessStatusCode)
            {
                var responseData = (JObject)JsonConvert.DeserializeObject(postResult.Content.ToString());
                VerifySignature(responseData);

                result = responseData["payload"].Value<string>();
            }
            else
            {
                result = string.Format("Something went wrong.\nDetails: {0}", postResult.ToString());
            }

            Console.WriteLine(result);
            return result;
        }

        private bool VerifySignature(JObject data)
        {
            // TODO Ensure fields exist

            var payloadString = data["payload"].Value<string>();
            var payload = (JObject)JsonConvert.DeserializeObject(payloadString);
            var signature = data["signature"].Value<string>();

            if (payload["method"].Value<string>() == "connect")
            {
                ServerPublicKey = payload["pubkey"].Value<string>();
                SessionId = payload["session_id"].Value<string>();
            }

            // This signature verification hasn't been tested yet and might not work.
            var isValid = RSAKeyUtilities.VerifyData(payloadString, HASHING_ALGORITHM, signature, PublicKey);
            return isValid;
        }
    }
}
