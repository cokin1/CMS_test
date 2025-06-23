using System;
using System.Web;
using System.Web.SessionState;
using System.Net;
using Microsoft.IdentityModel.Logging;

namespace KalikoCMS
{
    public class Global : System.Web.HttpApplication
    {
        protected void Application_Start(object sender, EventArgs e)
        {
            // This line reveals detailed errors. You can comment it out in production.
            IdentityModelEventSource.ShowPII = true;

            // This line forces modern security protocols. Keep it.
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;

            // This method should be empty. The CMS initializes itself automatically.
        }
    }
}