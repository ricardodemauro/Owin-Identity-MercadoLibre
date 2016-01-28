using CARD10.Owin.Security.MercadoLibre.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;
using System;
using System.Globalization;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Owin.Security;

namespace CARD10.Owin.Security.MercadoLibre
{
    public class MercadoLibreAuthenticationMiddleware : AuthenticationMiddleware<MercadoLibreAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public MercadoLibreAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, MercadoLibreAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrWhiteSpace(Options.AppId))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "AppId"));
            }
            if (string.IsNullOrWhiteSpace(Options.AppSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, Resources.Exception_OptionMustBeProvided, "AppSecret"));
            }

            _logger = app.CreateLogger<MercadoLibreAuthenticationMiddleware>();

            if (Options.Provider == null)
            {
                Options.Provider = new MercadoLibreAuthenticationProvider();
            }
            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(typeof(MercadoLibreAuthenticationMiddleware).FullName, Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options));
            _httpClient.Timeout = Options.BackchannelTimeout;
            _httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 mb
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(MercadoLibreAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new System.Net.Http.WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException(Resources.Exception_ValidatorHandlerMismatch);
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }

        protected override AuthenticationHandler<MercadoLibreAuthenticationOptions> CreateHandler()
        {
            return new MercadoLibreAuthenticationHandler(_httpClient, _logger);
        }

        public override Task Invoke(IOwinContext context)
        {
            return base.Invoke(context);
        }
    }
}
