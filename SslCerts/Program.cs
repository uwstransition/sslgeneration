using CertificateManager;
using CertificateManager.Models;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SslCerts
{
    class Program
    {
        private const string hostName = "local-locationdatamanagement.lmig.com";

        static void Main(string[] args)
        {
            var serviceProvider = new ServiceCollection()
                .AddCertificateManager()
                .BuildServiceProvider();
            var createClientServerAuthCerts = serviceProvider.GetService<CreateCertificatesClientServerAuth>();
            string password = CreatePassword(60);
            
            var client = createClientServerAuthCerts.NewServerSelfSignedCertificate(
                new DistinguishedName { CommonName = hostName, Country = "GB" },
                new ValidityPeriod { ValidFrom = DateTime.UtcNow, ValidTo = DateTime.UtcNow.AddYears(10) },
                hostName);
            client.FriendlyName = hostName;
             
            var importExportCertificate = serviceProvider.GetService<ImportExportCertificate>();
            var clientCertInPfxBtyes = importExportCertificate.ExportSelfSignedCertificatePfx(password, client);
            var exportableCert = new X509Certificate2(clientCertInPfxBtyes, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(exportableCert);
            store.Close();

            X509Store rootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            rootStore.Open(OpenFlags.ReadWrite);
            rootStore.Add(exportableCert);
            rootStore.Close();
        }

        public static string CreatePassword(int length)
        {
            const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            StringBuilder res = new StringBuilder();
            Random rnd = new Random();
            while (0 < length--)
            {
                res.Append(valid[rnd.Next(valid.Length)]);
            }
            return res.ToString();
        }
    }
}
