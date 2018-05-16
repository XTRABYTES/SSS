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

            // TODO: FIXME - This fails to very the signature from the server but works in everything else
            var isValid = RSAKeyUtilities.VerifyData(payloadString, HASHING_ALGORITHM, signature, PublicKey);
            return isValid;
        }
    }
}
