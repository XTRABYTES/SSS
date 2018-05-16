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
using System.Net;

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
            System.Net.ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
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
                { "password", password }
            });
        }

        public async Task<string> CheckUser(string username, string password)
        {
            return await Execute(new Dictionary<string, object>() {
                { "method", "CheckUser" },
                { "username", username },
                { "password", password }
            });
        }

        private async Task<string> Execute(Dictionary<string, object> parameters)
        {
            if (!string.IsNullOrWhiteSpace(SessionId))
            {
                parameters["session_id"] = SessionId;
            }

            var payload = JsonConvert.SerializeObject(parameters);
            var pemSignature = RSAKeyUtilities.ExportSignature(RSAKeyUtilities.SignData(payload, PrivateKey));

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

            var resultJson = await postResult.Content.ReadAsStringAsync();
            JObject parsedJson = JObject.Parse(resultJson);

            if (parsedJson.ContainsKey("payload"))
            {
                var resultPayload = (string)parsedJson["payload"];
                VerifySignature(parsedJson);
                result = resultPayload;
            }
            else if (parsedJson.ContainsKey("error"))
            {
                result = string.Format("SSS responded with an error: {0}", (string)parsedJson["error"]);
            }
            else
            {
                result = string.Format("SSS returned an unexpected response: {0}", postResult.ToString());
            }

            return result;
        }

        private bool VerifySignature(JObject data)
        {
            var isValid = false;

            if (data.ContainsKey("payload")
                && data.ContainsKey("signature"))
            {
                var payloadJson = (string)data["payload"];
                var parsedPayload = JObject.Parse(payloadJson);
                var signature = (string)data["signature"];

                if (parsedPayload.ContainsKey("method") 
                    && (string)parsedPayload["method"] == "connect"
                    && parsedPayload.ContainsKey("pubkey")
                    && parsedPayload.ContainsKey("session_id"))
                {
                    ServerPublicKey = (string)parsedPayload["pubkey"];
                    SessionId = (string)parsedPayload["session_id"];
                }

                isValid = RSAKeyUtilities.VerifyData(payloadJson, HASHING_ALGORITHM, signature, ServerPublicKey);
            }
            
            return isValid;
        }
    }
}
