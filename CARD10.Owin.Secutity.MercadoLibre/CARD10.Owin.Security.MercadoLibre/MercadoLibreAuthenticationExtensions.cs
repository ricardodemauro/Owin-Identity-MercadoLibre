using Owin;
using System;

namespace CARD10.Owin.Security.MercadoLibre
{
    public static class MercadoLibreAuthenticationExtensions
    {
        public static IAppBuilder UseMercadoLibreAuthentication(this IAppBuilder app, MercadoLibreAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");

            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(MercadoLibreAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseMercadoLibreAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            if (app == null)
                throw new ArgumentNullException("app");

            if (string.IsNullOrEmpty(appId))
                throw new ArgumentNullException("appId");

            if (string.IsNullOrEmpty(appSecret))
                throw new ArgumentNullException("appSecret");

            return UseMercadoLibreAuthentication(app, new MercadoLibreAuthenticationOptions()
            {
                AppId = appId,
                AppSecret = appSecret
            });
        }
    }
}
