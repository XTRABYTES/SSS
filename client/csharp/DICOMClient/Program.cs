using System;
using System.Threading.Tasks;

namespace DICOMClient
{
    class Program
    {
        const string HOST = "sss.xtrabytes.services";
        const int PORT = 8443;

        static void Main(string[] args)
        {
            var client = new DICOM.Client(HOST, PORT);
            client.Connect().Wait();

            // TODO Add remaining tests.

            Console.ReadLine();
        }
    }
}
