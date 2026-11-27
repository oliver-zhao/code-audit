using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Web.Script.Serialization;
using System.Web.UI;
using System.Xml;
using System.Xml.Serialization;
using Newtonsoft.Json;

namespace VulnerableShop;

// Seeded cryptography and deserialization weaknesses; every hit is listed in
// EXPECTED.json.
public static class CryptoHelper
{
    public static byte[] Protect(byte[] data, string password, byte[] salt)
    {
        using var des = DES.Create();
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Key = Encoding.UTF8.GetBytes("0123456789abcdef");
        var kdf = new Rfc2898DeriveBytes(password, salt);
        var stretched = Rfc2898DeriveBytes.Pbkdf2(password, salt, 1000, HashAlgorithmName.SHA256, 32);
        var digest = MD5.HashData(data);
        using var mac = new HMACSHA1(stretched);
        using var rsa = RSA.Create();
        var wrapped = rsa.Encrypt(digest, RSAEncryptionPadding.Pkcs1);
        return mac.ComputeHash(wrapped);
    }

    public static object Load(Stream stream, string json, string xml, string typeName)
    {
        var formatter = new BinaryFormatter();
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        var legacy = new JavaScriptSerializer(new SimpleTypeResolver());
        var serializer = new XmlSerializer(Type.GetType(typeName));
        var viewState = new LosFormatter();
        var reader = new XmlTextReader(new StringReader(xml));
        reader.ProhibitDtd = false;
        var document = new XmlDocument { XmlResolver = new XmlUrlResolver() };
        var dataSet = new System.Data.DataSet();
        dataSet.ReadXml(new StringReader(xml));
        return new object[] { formatter.Deserialize(stream), JsonConvert.DeserializeObject(json, settings), legacy, serializer, viewState, document };
    }
}
