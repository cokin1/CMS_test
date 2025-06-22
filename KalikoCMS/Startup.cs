using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(KalikoCMS.Startup))]
namespace KalikoCMS {

    public partial class Startup {
        public void Configuration(IAppBuilder app) {
            ConfigureAuth(app);
        }
    }
}