using System.Web;
using System.Web.Mvc;

namespace SafeShop.Legacy;

public class CommentModel
{
    public string Body { get; set; }
}

public class LegacyController : Controller
{
    [HttpPost]
    [ValidateAntiForgeryToken]
    public ActionResult Post(CommentModel model)
    {
        Response.Write("<p>Thanks, " + HttpUtility.HtmlEncode(Request.QueryString["name"]) + "</p>");
        return View(model);
    }
}
