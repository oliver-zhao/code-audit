using System.Web;
using System.Web.Mvc;

namespace VulnerableShop.Legacy;

// ASP.NET MVC 5 / System.Web seeds; every hit is listed in EXPECTED.json.
public class CommentModel
{
    [AllowHtml]
    public string Body { get; set; }
}

public class LegacyController : Controller
{
    [HttpPost]
    [ValidateInput(false)]
    public ActionResult Post(CommentModel model)
    {
        Response.Write("<p>Thanks, " + Request.QueryString["name"] + "</p>");
        return View(model);
    }
}
