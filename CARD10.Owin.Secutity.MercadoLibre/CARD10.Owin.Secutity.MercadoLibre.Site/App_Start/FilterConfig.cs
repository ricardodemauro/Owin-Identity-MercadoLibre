using System.Web;
using System.Web.Mvc;

namespace CARD10.Owin.Secutity.MercadoLibre.Site
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
