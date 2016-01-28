using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(CARD10.Owin.Secutity.MercadoLibre.Site.Startup))]
namespace CARD10.Owin.Secutity.MercadoLibre.Site
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
