# Single sign-on Ucommerce Hybrid

** THIS PROJECT IS PROVIDED AS IS **

This project is an example on how to configure Single sign-on (SSO) with Auth0 as the Identity Provider (IDP). 
This project uses Umbraco 11 and Umbraco 8.18, to demonstrate how to use an IDP to login the same user on two different Umbraco instances.

### Umbraco 11
Before you start there is a single dependency you need to install:

``` bash
dotnet add package Microsoft.AspNetCore.Authentication.OpenIdConnect
```

In the startup file, Umbraco add's the BackOffice to the service collection, with a default authentication handler. 
Here we will need to add an external provider, Umbraco comes with a method to do so `AddBackOfficeExternalLogins`.

`AddBackOfficeExternalLogins` lets you add handlers like `OpenIdConnect`, `Google` and many more.

``` csharp
var scheme = $"{Constants.Security.BackOfficeExternalAuthenticationTypePrefix}oidc";

services.AddUmbraco(_env, _config)
.AddBackOffice()
.AddBackOfficeExternalLogins(loginsBuilder =>
loginsBuilder.AddBackOfficeLogin(authBuilder =>
authBuilder.AddOpenIdConnect(scheme, "OpenID Connect", options =>
{
                options.Authority = "<Auth url>";
                options.ClientId = "interactive.confidential";
                options.ClientSecret = "secret";

                options.CallbackPath = "/signin-oidc";                
                options.ResponseType = "code";
                options.ResponseMode = "query";
                options.UsePkce = true;

                // get user identity
                options.Scope.Add("email");
                options.GetClaimsFromUserInfoEndpoint = true;
            })))
    .AddWebsite()
    .AddComposers()
    .Build();
```

** Note that the authentication scheme must start with “Umbraco.” **

After linking you profile you can disable the normal Umbraco login, by adding some provider options


``` csharp
var scheme = $"{Constants.Security.BackOfficeExternalAuthenticationTypePrefix}oidc";

services.AddUmbraco(_env, _config)
.AddBackOffice()
.AddBackOfficeExternalLogins(loginsBuilder =>
loginsBuilder.AddBackOfficeLogin(authBuilder =>
authBuilder.AddOpenIdConnect(scheme, "OpenID Connect", options =>
{
                options.Authority = "<Auth url>";
                options.ClientId = "interactive.confidential";
                options.ClientSecret = "secret";

                options.CallbackPath = "/signin-oidc";                
                options.ResponseType = "code";
                options.ResponseMode = "query";
                options.UsePkce = true;

                // get user identity
                options.Scope.Add("email");
                options.GetClaimsFromUserInfoEndpoint = true;
            }),
              providerOptions =>
              {
                  providerOptions.DenyLocalLogin = true;
                  providerOptions.AutoRedirectLoginToExternalProvider = true;
              }))
    .AddWebsite()
    .AddComposers()
    .Build();
```

### Umbraco 8.18

Umbraco 8 can be a little more tricky to setup, with SSO and require a little more work.
To add an IDP, we need to interrupt the OWIN pipelines. To do so we need to register our OWIN startup file.

In `Web.config`

``` xml
...
    <add key="owin:appStartup" value="UcommerceOwinStartup" />
...
```

Now it is time to create our custom OWIN file, here we use the value from above as the name

``` csharp
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
                                                     "<CLIENT_ID>",
                                                     "<CLIENT_SECRET>"
                                                    );
        }
    }
}

```

The `ConfigureBackOfficeOpenIdConnectAuth`, is a custom extension and look like this

``` csharp
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
```

## Final words
This is the work required to make a SSO login work across Umbraco 11 and Umbraco 8.
After this you can use the same login to access both Umbraco 8 and Umbraco 11.
An important note is, that it is not the same user, there is a user in both umbraco instances that points to our IDP. 