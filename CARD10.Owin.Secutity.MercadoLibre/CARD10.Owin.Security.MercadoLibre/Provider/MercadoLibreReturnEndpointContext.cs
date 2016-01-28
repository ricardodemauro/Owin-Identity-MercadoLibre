using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace CARD10.Owin.Security.MercadoLibre.Provider
{
    public class MercadoLibreReturnEndpointContext : ReturnEndpointContext
    {
        public MercadoLibreReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
            : base(context, ticket)
        { }
    }
}
