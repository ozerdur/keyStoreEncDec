using Microsoft.Extensions.Configuration;


CryptoUtil.LoadConfig();

Console.Write("Enter text to encrypt: ");
string originalText = Console.ReadLine();

string encryptedText = CryptoUtil.Encrypt(originalText);
Console.WriteLine("Encrypted Text: " + encryptedText);

Console.Write("Enter text to decrypt: ");
encryptedText = Console.ReadLine();

string decryptedText = CryptoUtil.Decrypt(encryptedText);
Console.WriteLine("Decrypted Text: " + decryptedText);
