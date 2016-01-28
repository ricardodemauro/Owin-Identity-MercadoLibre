using CARD10.Owin.Security.MercadoLibre.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CARD10.Owin.Security.MercadoLibre
{
    public class MercadoLibreAuthenticationHandler : AuthenticationHandler<MercadoLibreAuthenticationOptions>
    {
        private const string apiUrl = "https://api.mercadolibre.com";

        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string TokenEndpoint = "/oauth/token?grant_type=authorization_code&client_id={0}&client_secret={1}&code={2}&redirect_uri={3}";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public MercadoLibreAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected async override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string code = null;
                string state = null;

                IReadableStringCollection query = Request.Query;

                properties = UnpackStateParameter(query, out state);
                if (properties == null)
                {
                    _logger.WriteWarning("Invalid return state");
                    return null;
                }

                IList<string> values = query.GetValues("error");
                if (values != null && values.Count >= 1)
                {
                    _logger.WriteVerbose("Remote server returned an error: " + Request.QueryString);
                }

                values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }

                if (code == null)
                {
                    // Null if the remote server returns an error.
                    return new AuthenticationTicket(null, properties);
                }


                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = BuildReturnTo(state);

                string tokenPostUri = string.Concat(apiUrl, TokenEndpoint);
                Uri postUri = new Uri(string.Format(tokenPostUri,
                    Uri.EscapeDataString(Options.AppId),
                    Uri.EscapeDataString(Options.AppSecret),
                    Uri.EscapeDataString(code),
                    redirectUri), UriKind.Absolute);

                HttpResponseMessage tokenResponse = await _httpClient.PostAsync(postUri, null);
                tokenResponse.EnsureSuccessStatusCode();

                string text = await tokenResponse.Content.ReadAsStringAsync();

                JObject user = JObject.Parse(text);

                string accessToken = user["access_token"].Value<string>();
                string expires = user["expires_in"].Value<string>();

                var context = new MercadoLibreAuthenticatedContext(Context, user, accessToken, expires);

                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);
                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }
                context.Identity.AddClaim(new Claim("urn:mercadolibre:id", context.Id, XmlSchemaString, Options.AuthenticationType));

                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                AuthenticationProperties properties = challenge.Properties;
                string state = Options.StateDataFormat.Protect(properties);

                string redirectUri = BuildReturnTo(state);

                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                string authorizationEndpoint = string.Format("http://auth.mercadolivre.com.br/authorization?response_type=code&client_id={0}&redirect_uri={1}",
                    Uri.EscapeDataString(Options.AppId),
                    Uri.EscapeDataString(redirectUri));

                var redirectContext = new MercadoLibreApplyRedirectContext(
                    Context, Options,
                    properties, authorizationEndpoint);
                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }

        public async override Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                // TODO: error responses

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new MercadoLibreReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }

        private string BuildReturnTo(string state)
        {
            return Request.Scheme + "://" + Request.Host +
                RequestPathBase + Options.CallbackPath +
                "?state=" + Uri.EscapeDataString(state);
        }

        private AuthenticationProperties UnpackStateParameter(IReadableStringCollection query, out string state)
        {
            state = GetStateParameter(query);
            if (state != null)
            {
                return Options.StateDataFormat.Unprotect(state);
            }
            return null;
        }

        private static string GetStateParameter(IReadableStringCollection query)
        {
            IList<string> values = query.GetValues("state");
            if (values != null && values.Count == 1)
            {
                return values[0];
            }
            return null;
        }
    }
}
