using System;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace VulnerableShop;

// Seeded configuration weaknesses; every hit is listed in EXPECTED.json.
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                    RequireSignedTokens = false,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("vulnerable-shop-fixture-signing-key-0001")),
                };
            });

        services.AddCors(options => options.AddPolicy("open", policy =>
            policy.SetIsOriginAllowed(_ => true)
                .AllowAnyHeader()
                .AllowCredentials()));

        services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = false;
            options.Cookie.SameSite = SameSiteMode.None;
        });

        services.AddHttpClient("partner").ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true,
            CheckCertificateRevocationList = false,
            SslProtocols = SslProtocols.Tls11,
        });

        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseDeveloperExceptionPage();
        app.UseCors("open");
    }
}
