using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web.UI;

namespace myazurecorewebapppoc
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

         /*   * Multiple Authentication Providers Start

            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

             services.AddAuthentication(options =>
            {
               options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            }).AddCookie(options =>
            {
               options.LoginPath = "/account/login";
            }).AddGoogle(googleOptions =>
            {
                googleOptions.ClientId = Configuration["Authentication:Google:ClientId"];
                googleOptions.ClientSecret = Configuration["Authentication:Google:ClientSecret"];
            }).AddFacebook(facebookOptions =>
            {
                facebookOptions.AppId = Configuration["Authentication:Facebook:AppId"];
                facebookOptions.AppSecret = Configuration["Authentication:Facebook:AppSecret"];
            });
             
            * Multiple Authentication Providers End */

            services.AddAuthentication(AzureADDefaults.AuthenticationScheme)
            .AddAzureAD(options => Configuration.Bind("AzureAd", options)); 

            //services.AddAuthentication(options =>
            //{
            //    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            //}).AddCookie(options =>
            //{
            //    options.LoginPath = "/account/login";
            //}).AddFacebook(facebookOptions =>
            //{
            //    facebookOptions.AppId = "476695353323105";
            //    facebookOptions.AppSecret = "3ff6c14b20c53a20f1e7ea5d0923eafb";
            //});

            /*      services.AddAuthentication().AddFacebook(facebookOptions => 
                 {
                     facebookOptions.AppId = "476695353323105";
                     facebookOptions.AppSecret = "3ff6c14b20c53a20f1e7ea5d0923eafb";

                     facebookOptions.Events = new OAuthEvents()
                     {
                         OnRemoteFailure = loginFailureHandler =>
                         {
                             var authProperties = facebookOptions.StateDataFormat.Unprotect(loginFailureHandler.Request.Query["state"]);
                             loginFailureHandler.Response.Redirect("/Identity/Account/Login");
                             loginFailureHandler.HandleResponse();
                             return Task.FromResult(0);
                         }
                     };
                 }); */

            /*  services.Configure<OpenIdConnectAuthenticationOptions>(AzureADDefaults.OpenIdScheme, options =>
             {
                 options.Authority = options.Authority + "/v2.0/";
                 options.TokenValidationParameters.ValidateIssuer = false;
             }); */


            services.AddControllersWithViews(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            });
                
            services.AddAuthorization(options => {
                   options.AddPolicy("DivisionManager",policyBuilder => policyBuilder.RequireClaim("groups","779b7664-f019-4e31-98b4-468c293e1129"));
               });


          services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }
    }
}
