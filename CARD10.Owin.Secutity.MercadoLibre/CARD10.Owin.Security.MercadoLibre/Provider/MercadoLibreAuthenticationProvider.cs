using System;
using System.Threading.Tasks;

namespace CARD10.Owin.Security.MercadoLibre.Provider
{
    public class MercadoLibreAuthenticationProvider : IMercadoLibreAuthenticationProvider
    {
        public MercadoLibreAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
            OnApplyRedirect = context => context.Response.Redirect(context.RedirectUri);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<MercadoLibreAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<MercadoLibreReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the delegate that is invoked when the ApplyRedirect method is invoked.
        /// </summary>
        public Action<MercadoLibreApplyRedirectContext> OnApplyRedirect { get; set; }

        public virtual Task Authenticated(MercadoLibreAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public virtual Task ReturnEndpoint(MercadoLibreReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }

        public virtual void ApplyRedirect(MercadoLibreApplyRedirectContext context)
        {
            OnApplyRedirect(context);
        }
    }
}
