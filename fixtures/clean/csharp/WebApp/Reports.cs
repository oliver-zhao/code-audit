using System.Collections.Generic;
using System.Xml;

namespace SafeShop;

public static class Reports
{
    private static readonly Dictionary<string, string> Sections = new()
    {
        ["sales"] = "/report/sales/item[@visible='true']",
        ["stock"] = "/report/stock/item[@visible='true']",
    };

    public static XmlNodeList Section(XmlDocument doc, string section)
    {
        return Sections.TryGetValue(section, out var query) ? doc.SelectNodes(query) : null;
    }
}
