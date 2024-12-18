﻿
Console.Write("KeyStore File Yaratmak istiyor musunuz?  Y/N: ");
string answer = Console.ReadLine();

CryptoUtil.LoadConfig();

if(answer.Equals("Y", StringComparison.OrdinalIgnoreCase))
{
  Console.Write("Enter KeyStore Key: ");
    
    string key = Console.ReadLine();

    CryptoUtil.WriteKeyValueToKeystore(CryptoUtil.storeAlias, key);
}

CryptoUtil.LoadKeys();

Console.Write("Enter text to encrypt: ");
string originalText = Console.ReadLine();

string encryptedText = CryptoUtil.Encrypt(originalText);
Console.WriteLine("Encrypted Text: " + encryptedText);

Console.Write("Enter text to decrypt: ");
encryptedText = Console.ReadLine();

string decryptedText = CryptoUtil.Decrypt(encryptedText);
Console.WriteLine("Decrypted Text: " + decryptedText);
