using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Umbraco.Core;
using Umbraco.Web.Security;

namespace Ucommerce.Umbraco818.Extensions
{
    /// <summary>
    /// A class to implement OpenID Connect single-sign on with Umbraco 8's back office.
    /// 
    /// Make sure you install the NuGet package Microsoft.Owin.Security.OpenIDConnect v4.0.1 or better
    /// </summary>
    public static class OpenIdAuthConnectExtensions
    {
        /// <summary>
        /// Configures Umbraco to use a customized OpenID Connect authentication. This example is meant to work with Auth0.
        /// </summary>
        /// <param name="app">OWIN Middleware pipeline constructor</param>
        /// <param name="authority">The location of your OpenID Connect server</param>
        /// <param name="redirectUri">The location of the Umbraco back office; where OpenID Connect will redirect to when login and logout actions are performed</param>
        /// <param name="clientId">Client id</param>
        /// <param name="clientSecret">Client secret</param>
        public static void ConfigureBackOfficeOpenIdConnectAuth(this IAppBuilder app,
                                                                string authority,
                                                                string redirectUri,
                                                                string clientId,
                                                                string clientSecret)
        {
            var identityOptions = new OpenIdConnectAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                SignInAsAuthenticationType = Constants.Security.BackOfficeExternalAuthenticationType,
                AuthenticationType = authority,
                Authority = authority,
                RedirectUri = redirectUri,
                ResponseType = "code id_token token",
                Scope = "openid email profile application.profile",
                PostLogoutRedirectUri = redirectUri,

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = GenerateUserIdentityAsync
                }
            };

            // Configure BackOffice Account Link button and style
            identityOptions.ForUmbracoBackOffice("btn-microsoft", "fa-windows");
            identityOptions.Caption = "OpenId Connect";

            identityOptions.AuthenticationType = authority;

            // Configure AutoLinking
            identityOptions.SetBackOfficeExternalLoginProviderOptions(new BackOfficeExternalLoginProviderOptions
            {
                AutoLinkOptions = new ExternalSignInAutoLinkOptions()
            });

            app.UseOpenIdConnectAuthentication(identityOptions);
        }

        private static async Task GenerateUserIdentityAsync(
            SecurityTokenValidatedNotification<OpenIdConnectMessage,
                OpenIdConnectAuthenticationOptions> notification)
        {
            var identityUser = new ClaimsIdentity(
                                                  notification.AuthenticationTicket.Identity.Claims,
                                                  notification.AuthenticationTicket.Identity.AuthenticationType,
                                                  ClaimTypes.Name,
                                                  ClaimTypes.Role);

            var newIdentityUser = new ClaimsIdentity(identityUser.AuthenticationType,
                                                     ClaimTypes.GivenName,
                                                     ClaimTypes.Role);

            newIdentityUser.AddClaim(identityUser.FindFirst(ClaimTypes.NameIdentifier));

            var emailClaim = identityUser.FindFirst(ClaimTypes.Email) ?? new Claim(ClaimTypes.Email,
                                                                                   identityUser.FindFirst("name")
                                                                                               .Value);
            newIdentityUser.AddClaim(emailClaim);

            notification.AuthenticationTicket = new AuthenticationTicket(newIdentityUser,
                                                                         notification.AuthenticationTicket.Properties);

            await Task.CompletedTask;
        }
    }
}
