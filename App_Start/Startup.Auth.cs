using AspNet.Identity.DataAccess;
using AspNet.Identity.DataAccess.Data;
using KalikoCMS.Identity;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Configuration;
using System.Globalization;
using System.Security.Claims;
using System.Threading.Tasks;

namespace KalikoCmsClean
{
    public partial class Startup
    {
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        private static string postLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];
        private static string authority = String.Format(CultureInfo.InvariantCulture, aadInstance, tenant);

        public void ConfigureAuth(IAppBuilder app)
        {
            app.CreatePerOwinContext(DataContext.Create);
            app.CreatePerOwinContext<IdentityUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            app.SetDefaultSignInAsAuthenticationType(DefaultAuthenticationTypes.ApplicationCookie);

            var cookieManager = new SystemWebCookieManager();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login.aspx"),
                CookieManager = cookieManager,
                Provider = new CookieAuthenticationProvider
                {
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, IdentityUser, Guid>(
                        TimeSpan.FromMinutes(30),
                        (manager, user) => user.GenerateUserIdentityAsync(manager),
                        (id) => new Guid(id.GetUserId()))
                }
            });

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = clientId,
                    Authority = authority,
                    PostLogoutRedirectUri = postLogoutRedirectUri,
                    CookieManager = cookieManager,

                    // --- FINAL WORKAROUND: Bypassing the nonce check ---
                    //ProtocolValidator = new OpenIdConnectProtocolValidator
                    //{
                    //    RequireNonce = false
                    //},

                    Notifications = new OpenIdConnectAuthenticationNotifications()
                    {
                        SecurityTokenValidated = async (context) =>
                        {
                            var owinContext = context.OwinContext;
                            var userManager = owinContext.GetUserManager<IdentityUserManager>();
                            var providerKey = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
                            var loginInfo = new UserLoginInfo(DefaultAuthenticationTypes.ExternalCookie, providerKey);
                            var user = await userManager.FindAsync(loginInfo);

                            if (user != null)
                            {
                                var signInManager = owinContext.Get<ApplicationSignInManager>();
                                await signInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                            }
                            else
                            {
                                context.HandleResponse();
                                context.Response.Redirect("/Account/Login.aspx?error=External account not linked");
                            }
                        },
                        AuthenticationFailed = (context) =>
                        {
                            context.HandleResponse();
                            context.Response.Redirect("/Error.aspx?message=" + context.Exception.Message);
                            return Task.FromResult(0);
                        }
                    }
                });
        }
    }
}