using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(KalikoCmsClean.Startup))]
namespace KalikoCmsClean
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // This line calls the ConfigureAuth method located in your other file, App_Start/Startup.Auth.cs
            ConfigureAuth(app);
        }
    }
}