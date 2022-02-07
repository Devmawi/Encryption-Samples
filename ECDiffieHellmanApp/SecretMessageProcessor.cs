using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ECDiffieHellmanApp
{
    public class SecretMessageProcessor
    {
        public ECDiffieHellman ECDiffieHellman { get; set; } = ECDiffieHellman.Create();
        public ECDiffieHellmanPublicKey PublicKey => ECDiffieHellman.PublicKey;

        public async Task<(byte[], byte[])> CreateEncodedMessageAsync(ECDiffieHellmanPublicKey otherKey, string message)
        {
            var symkey = ECDiffieHellman.DeriveKeyMaterial(otherKey);
            var aes = Aes.Create();
            aes.Key = symkey;
            aes.GenerateIV();

            ICryptoTransform cryptoTransform = aes.CreateEncryptor();
            MemoryStream ms = new();
            using (CryptoStream cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                var plainData = System.Text.Encoding.UTF8.GetBytes(message);
                await cs.WriteAsync(plainData.AsMemory());
            }
            return (aes.IV, ms.ToArray());
        }

        public (string, string) ExportPublicPrivateKeyPair(string name)
        {
            ECDiffieHellman alg = ECDiffieHellman;
            var (publicKey, privateKey) = (alg.ExportSubjectPublicKeyInfo(), alg.ExportPkcs8PrivateKey());

            var publicKeyFile = Path.Combine(AppContext.BaseDirectory, $"{name}_PublicKey");
            var privateKeyFile = Path.Combine(AppContext.BaseDirectory, $"{name}_PrivateKey");
            File.WriteAllBytes(publicKeyFile, publicKey);
            File.WriteAllBytes(privateKeyFile, privateKey);
            return (publicKeyFile, privateKeyFile);
        }

        public byte[] ExportPublicKey()
        {
            return PublicKey.ToByteArray();
        }

        public async Task<string> DecodeMessage(ECDiffieHellmanPublicKey otherKey, byte[] iv, byte[] data)
        {
            
            var symkey = ECDiffieHellman.DeriveKeyMaterial(otherKey);
            var aes = Aes.Create();
            aes.Key = symkey;
            aes.IV = iv;

            ICryptoTransform cryptoTransform = aes.CreateDecryptor();
            MemoryStream ms = new();
            using (CryptoStream cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                await cs.WriteAsync(data.AsMemory());
            }
            return System.Text.Encoding.UTF8.GetString(ms.ToArray());
        }

        public async Task<string> DecodeMessage(byte[] publicKeyFile, byte[] iv, byte[] data)
        {

            var publicKeyFromFile = ECDiffieHellmanCngPublicKey.FromByteArray(publicKeyFile, CngKeyBlobFormat.EccPublicBlob);
          
             var symkey = ECDiffieHellman.DeriveKeyMaterial(publicKeyFromFile);
            var aes = Aes.Create();
            aes.Key = symkey;
            aes.IV = iv;

            ICryptoTransform cryptoTransform = aes.CreateDecryptor();
            MemoryStream ms = new();
            using (CryptoStream cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                await cs.WriteAsync(data.AsMemory());
            }
            return System.Text.Encoding.UTF8.GetString(ms.ToArray());
        }

        public async Task<string> DecodeMessage(string publicKeyFile, byte[] iv, byte[] data)
        {

            var alg = ECDiffieHellman.Create();
            alg.ImportSubjectPublicKeyInfo(File.ReadAllBytes(publicKeyFile), out int bytesRead);

            var symkey = ECDiffieHellman.DeriveKeyMaterial(alg.PublicKey);
            var aes = Aes.Create();
            aes.Key = symkey;
            aes.IV = iv;

            ICryptoTransform cryptoTransform = aes.CreateDecryptor();
            MemoryStream ms = new();
            using (CryptoStream cs = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                await cs.WriteAsync(data.AsMemory());
            }
            return System.Text.Encoding.UTF8.GetString(ms.ToArray());
        }
    }
}
