using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Configuration;


public class CryptoUtil
{

    public static string encryption_key_store_path =  "ws.encription.key.store.path";
    public static string encription_parameter_spec_iv_value ="ws.encription.parameter.spec.iv.value";
    public static string  encryption_key_store_password = "ws.encription.key.store.password";
    public static string  encryption_key_store_alias = "ws.encription.key.store.alias";

    private static string filePath;
    private static string storeKey;
    private static byte[] keyBytes;
    private static byte[] ivBytes;
    private static string key;
    
    public static string Encrypt(string data)
    {
        using (var aes = Aes.Create())
        {
            aes.Key = Encoding.UTF8.GetBytes(key);
            aes.IV = ivBytes;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            {
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] encryptedBytes = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
                return Convert.ToBase64String(encryptedBytes);
            }
        }
    }

    public static string Decrypt(string encryptedData)
    {
        using (var aes = Aes.Create())
        {
            aes.Key =  Encoding.UTF8.GetBytes(key);
            aes.IV = ivBytes;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                byte[] encryptedBytes = Convert.FromBase64String(encryptedData);
                byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
    }

    public static void WriteKeyValueToKeystore(string alias, string keyValue)
    {
        var ks = new X509Certificate2Collection();
        if (!File.Exists(filePath))
        {
            using (var rsa = RSA.Create())
            {
                var request = new CertificateRequest($"cn={alias}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                var newCert = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(50));
                ks.Add(newCert);
                File.WriteAllBytes(filePath, newCert.Export(X509ContentType.Pfx, storeKey));
            }
        }

        ks.Import(filePath, storeKey, X509KeyStorageFlags.DefaultKeySet);
        var cert = ks.Find(X509FindType.FindBySubjectName, alias, false)[0];

        using (var rsa = cert.GetRSAPrivateKey())
        {
            if (rsa == null)
            {
                throw new InvalidOperationException("Certificate does not have a private key.");
            }

            var keyBytes = Encoding.UTF8.GetBytes(keyValue);
            var encryptedKey = rsa.Encrypt(keyBytes, RSAEncryptionPadding.OaepSHA256);
            File.WriteAllBytes($"{alias}.key", encryptedKey);
        }
    }

    public static string ReadKeyValueFromKeystore(string alias)
    {
        var ks = new X509Certificate2Collection();
        ks.Import(filePath, storeKey, X509KeyStorageFlags.DefaultKeySet);
        var cert = ks.Find(X509FindType.FindBySubjectName, alias, false)[0];

        using (var rsa = cert.GetRSAPrivateKey())
        {
            if (rsa == null)
            {
                throw new InvalidOperationException("Certificate does not have a private key.");
            }

            var encryptedKey = File.ReadAllBytes($"{alias}.key");
            var decryptedKey = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
            return Encoding.UTF8.GetString(decryptedKey);
        }
    }

    public static void LoadConfig()
    {
        var builder = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("config.json");

        IConfigurationRoot configuration = builder.Build();

        filePath = configuration[encryption_key_store_path] ?? throw new ArgumentNullException(encryption_key_store_path);
        string iv = configuration[encription_parameter_spec_iv_value] ?? throw new ArgumentNullException(encription_parameter_spec_iv_value);
        storeKey = configuration[encryption_key_store_password] ?? throw new ArgumentNullException(encryption_key_store_password);
        string storeAlias = configuration[encryption_key_store_alias] ?? throw new ArgumentNullException(encryption_key_store_alias);


        WriteKeyValueToKeystore(storeAlias, "abcdefghijklmnop");

        key =ReadKeyValueFromKeystore(storeAlias);


        ivBytes = Encoding.UTF8.GetBytes(iv);
    }


}