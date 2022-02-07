using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace ECDiffieHellmanApp
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Let's Encrypt");
            // .p8
            //https://www.microfocus.com/documentation/visual-cobol/VC40/CSWin/BKCJCJCERTS001.html
            var alice = new SecretMessageProcessor();
            var bob = new SecretMessageProcessor();

            var message = "Hello Encrypting";
            var (iv, encodedMessage) = await alice.CreateEncodedMessageAsync(bob.PublicKey, message);
            //var decodedMessage = await bob.DecodeMessage(alice.PublicKey, iv, encodedMessage);

            Console.WriteLine($"Encoded message: {System.Text.Encoding.UTF8.GetString(encodedMessage)}");

            var (publicKeyFile, privateKeyFile) = alice.ExportPublicPrivateKeyPair("Alice");
            var publicKey = alice.ExportPublicKey();

            var decodedMessageFromFile = await bob.DecodeMessage(publicKeyFile, iv, encodedMessage);
            var decodedMessageFromKeyContent = await bob.DecodeMessage(publicKey, iv, encodedMessage);

            Console.WriteLine($"Decoded message: {decodedMessageFromFile}");
            // var susan = new SecretMessageProcessor();
           // await susan.DecodeMessage(publicKey, iv, encodedMessage); Throws Exception
        }
    }
}
