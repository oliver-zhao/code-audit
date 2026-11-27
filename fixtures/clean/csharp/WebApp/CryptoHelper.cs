using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;

namespace SafeShop;

public static class CryptoHelper
{
    public static byte[] Protect(byte[] data, byte[] key, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var stretched = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600000, HashAlgorithmName.SHA256, 32);
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var cipher = new byte[data.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        using var aes = new AesGcm(key, tag.Length);
        aes.Encrypt(nonce, data, cipher, tag);
        var digest = SHA256.HashData(cipher);
        using var mac = new HMACSHA256(stretched);
        using var rsa = RSA.Create();
        var wrapped = rsa.Encrypt(digest, RSAEncryptionPadding.OaepSHA256);
        return mac.ComputeHash(wrapped);
    }

    public static T Load<T>(string json, string xml)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        using var reader = XmlReader.Create(new StringReader(xml), settings);
        while (reader.Read())
        {
        }
        return JsonSerializer.Deserialize<T>(json);
    }
}
