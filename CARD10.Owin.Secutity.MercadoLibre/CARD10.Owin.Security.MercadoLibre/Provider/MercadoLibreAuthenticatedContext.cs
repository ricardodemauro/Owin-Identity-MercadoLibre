using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System;
using System.Globalization;
using System.Security.Claims;

namespace CARD10.Owin.Security.MercadoLibre.Provider
{
    public class MercadoLibreAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="MercadoLibreAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">MercadoLibre Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public MercadoLibreAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string expires)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }

            RefreshToken = TryGetValue(user, "refresh_token");
            //user["token_type"].Value<string>();
            Id = TryGetValue(user, "user_id");
            //user["scope"].Value<string>();
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Mercado Libre access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Mercado Libre refresh token
        /// </summary>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the Facebook access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        public string Id { get; private set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
