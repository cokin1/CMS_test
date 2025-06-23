using System;
using System.Web;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;

// The namespace MUST match your new project name
namespace KalikoCmsClean
{
    public partial class Login : System.Web.UI.Page
    {
        protected void LogIn(object sender, EventArgs e)
        {
            if (!IsValid)
            {
                return;
            }

            var signinManager = Context.GetOwinContext().GetUserManager<ApplicationSignInManager>();
            var result = signinManager.PasswordSignIn(Email.Text, Password.Text, RememberMe.Checked, shouldLockout: false);

            switch (result)
            {
                case SignInStatus.Success:
                    RedirectToReturnUrl(Request.QueryString["ReturnUrl"], Response);
                    break;
                case SignInStatus.LockedOut:
                    // Redirecting to an error page is safer as the old Utils class may not exist
                    Response.Redirect("/Error.aspx?message=Account locked out");
                    break;
                case SignInStatus.RequiresVerification:
                    // Implement verification here if wanted
                    break;
                case SignInStatus.Failure:
                default:
                    FailureText.Text = "Invalid login attempt";
                    ErrorMessage.Visible = true;
                    break;
            }
        }

        protected void AzureAdLoginButton_Click(object sender, EventArgs e)
        {
            // This tells the application to start the Azure AD (Entra ID) login process
            HttpContext.Current.GetOwinContext().Authentication.Challenge(
                new AuthenticationProperties { RedirectUri = "/Admin" },
                OpenIdConnectAuthenticationDefaults.AuthenticationType
            );
        }

        public static void RedirectToReturnUrl(string returnUrl, HttpResponse response)
        {
            if (!String.IsNullOrEmpty(returnUrl) && IsLocalUrl(returnUrl))
            {
                response.Redirect(returnUrl);
            }
            else
            {
                response.Redirect("~/");
            }
        }

        private static bool IsLocalUrl(string url)
        {
            return !string.IsNullOrEmpty(url) && ((url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'))) || (url.Length > 1 && url[0] == '~' && url[1] == '/'));
        }
    }
}