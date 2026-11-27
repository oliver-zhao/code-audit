using System.Xml;

namespace VulnerableShop;

// Seeded XPath hotspot; every hit is listed in EXPECTED.json.
public static class Reports
{
    public static XmlNodeList Section(XmlDocument doc, string section)
    {
        return doc.SelectNodes("/report/" + section + "/item[@visible='true']");
    }
}
