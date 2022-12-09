using Microsoft.Owin;
using Owin;
using Ucommerce.Umbraco818;
using Ucommerce.Umbraco818.Extensions;
using Umbraco.Web;

[assembly: OwinStartup("UcommerceOwinStartup", typeof(UcommerceOwinStartup))]

namespace Ucommerce.Umbraco818
{
    /// <summary>
    /// OWIN Startup class for UcommerceOwinStartup 
    /// </summary>
    public class UcommerceOwinStartup : UmbracoDefaultOwinStartup
    {
        protected override void ConfigureUmbracoAuthentication(IAppBuilder app)
        {
            
            base.ConfigureUmbracoAuthentication(app);
            app.ConfigureBackOfficeOpenIdConnectAuth(
                                                     "https://dev-du4ozbiumcte1t0u.eu.auth0.com", // Location of the OpenIDConnect server
                                                     "https://localhost:44394/umbraco", // Location of the back office
                                                     "gvMmTqJknY2eOpRT1r13UoKWoCQ0AGue",
                                                     "JUEVACOgLoYwBdF7Yx7uqGuOaVYZaCkemnc1xR7GfL_3lZrLLHv-7zHcAL1PuP5D"
                                                    );
        }
    }
}
