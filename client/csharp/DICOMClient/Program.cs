using System;
using System.Threading.Tasks;

namespace DICOMClient
{
    class Program
    {
        const string HOST = "sss.xtrabytes.services";
        const int PORT = 8443;

        public static async Task Main(string[] args)
        {
            var client = new DICOM.Client(HOST, PORT);
            string result;

            result = await client.Connect();
            Console.WriteLine(result);

            result = await client.CreateUser("danny", "foobarbaz");
            Console.WriteLine(result);

            result = await client.CheckUsername("danny");
            Console.WriteLine(result);

            result = await client.CheckUser("danny", "foobarbaz");
            Console.WriteLine(result);

            Console.ReadKey();
        }
    }
}
