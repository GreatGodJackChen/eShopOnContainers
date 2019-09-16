// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using IdentityServer.Data;
using IdentityServer.Models;
using IdentityServer.Services;
using IdentityServer4;
using IdentityServer4.EntityFramework.DbContexts;
using IdentityServer4.EntityFramework.Mappers;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer
{
    public class Startup
    {
        public IHostingEnvironment Environment { get; }
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration, IHostingEnvironment environment)
        {
            Configuration = configuration;
            Environment = environment;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc().SetCompatibilityVersion(Microsoft.AspNetCore.Mvc.CompatibilityVersion.Version_2_1);
            services.AddCors(options =>
            {
                // this defines a CORS policy called "default"
                options.AddPolicy("default", policy =>
                {
                    policy.WithOrigins("http://localhost:4200")
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });
            //var builder = services.AddIdentityServer()
            //    .AddInMemoryIdentityResources(Config.GetIdentityResources())
            //    .AddInMemoryApiResources(Config.GetApis())
            //    .AddInMemoryClients(Config.GetClients())
            //    .AddTestUsers(Config.GetUsers());
            services.AddTransient<ILoginService<ApplicationUser>, EFLoginService>();
            services.AddTransient<IRedirectService, RedirectService>();

            var connectionString = Configuration["ConnectionString"];
            var migrationsAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            //注入dbcontext
            services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(connectionString,
               sqlServerOptionsAction: sqlOptions =>
               {
                   sqlOptions.MigrationsAssembly(typeof(Startup).GetTypeInfo().Assembly.GetName().Name);
                   //Configuring Connection Resiliency: https://docs.microsoft.com/en-us/ef/core/miscellaneous/connection-resiliency 
                   sqlOptions.EnableRetryOnFailure(maxRetryCount: 15, maxRetryDelay: TimeSpan.FromSeconds(30), errorNumbersToAdd: null);
               }));

            // 映射自定义的User，Role
            services.AddIdentity<ApplicationUser, IdentityRole>() // 映射自定义的User，Role
                .AddEntityFrameworkStores<ApplicationDbContext>() //配置使用EF持久化存储
                .AddDefaultTokenProviders(); //配置默认的TokenProvider用于变更密码和修改email时生成Token


            var builder = services.AddIdentityServer()
                .AddAspNetIdentity<ApplicationUser>()
            .AddDeveloperSigningCredential()
            .AddConfigurationStore(options =>
            {
                options.ConfigureDbContext = b => b.UseSqlServer(connectionString,
                    sqlServerOptionsAction: sqlOptions =>
                    {
                        sqlOptions.MigrationsAssembly(migrationsAssembly);
                        //Configuring Connection Resiliency: https://docs.microsoft.com/en-us/ef/core/miscellaneous/connection-resiliency 
                        //解决短暂的数据库连接失败问题
                        sqlOptions.EnableRetryOnFailure(maxRetryCount: 15, maxRetryDelay: TimeSpan.FromSeconds(30), errorNumbersToAdd: null);
                    });
            })
            .AddOperationalStore(options =>
            {
                options.ConfigureDbContext = b => b.UseSqlServer(connectionString,
                    sqlServerOptionsAction: sqlOptions =>
                    {
                        sqlOptions.MigrationsAssembly(migrationsAssembly);
                        //Configuring Connection Resiliency: https://docs.microsoft.com/en-us/ef/core/miscellaneous/connection-resiliency 
                        //解决短暂的数据库连接失败问题
                        sqlOptions.EnableRetryOnFailure(maxRetryCount: 15, maxRetryDelay: TimeSpan.FromSeconds(30), errorNumbersToAdd: null);
                    });
            });
            //在IdentityServer4中添加自定义声明我们需要实现IProfileService接口
            //.Services.AddTransient<IProfileService, ProfileService>();

            if (Environment.IsDevelopment())
            {
                builder.AddDeveloperSigningCredential();
            }
            else
            {
                throw new Exception("need to configure key material");
            }

            //services.AddAuthentication()
            //    .AddGoogle("Google", options =>
            //    {
            //        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

            //        options.ClientId = "<insert here>";
            //        options.ClientSecret = "<insert here>";
            //    })
            //    .AddOpenIdConnect("oidc", "OpenID Connect", options =>
            //    {
            //        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
            //        options.SignOutScheme = IdentityServerConstants.SignoutScheme;
            //        options.SaveTokens = true;

            //        options.Authority = "https://demo.identityserver.io/";
            //        options.ClientId = "implicit";

            //        options.TokenValidationParameters = new TokenValidationParameters
            //        {
            //            NameClaimType = "name",
            //            RoleClaimType = "role"
            //        };
            //    });
        }

        public void Configure(IApplicationBuilder app)
        {
            if (Environment.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseCors("default");
            InitializeDatabase(app);
            app.UseStaticFiles();

            app.UseIdentityServer();

            app.UseMvcWithDefaultRoute();
        }
        private void InitializeDatabase(IApplicationBuilder app)
        {
            //初始配置
            using (var serviceScope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            {
                serviceScope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.Migrate();

                var context = serviceScope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();
                context.Database.Migrate();

                //var clientUrls = new Dictionary<string, string>();
                //clientUrls.Add("Spa", Configuration.GetValue<string>("SpaClient"));
                //clientUrls.Add("SpaTest", Configuration.GetValue<string>("SpaTest"));
                if (!context.Clients.Any())
                {
                    foreach (var client in Config.GetClients())
                    {
                        context.Clients.Add(client.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.IdentityResources.Any())
                {
                    foreach (var resource in Config.GetIdentityResources())
                    {
                        context.IdentityResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }

                if (!context.ApiResources.Any())
                {
                    foreach (var resource in Config.GetApis())
                    {
                        context.ApiResources.Add(resource.ToEntity());
                    }
                    context.SaveChanges();
                }
                var appcontext = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                appcontext.Database.Migrate();
                if (!appcontext.Users.Any())
                {
                    appcontext.Users.AddRange(GetDefaultUser());

                    appcontext.SaveChanges();
                }
            }
        }
        private IEnumerable<ApplicationUser> GetDefaultUser()
        {
            var user =
            new ApplicationUser()
            {
                CardHolderName = "DemoUser",
                CardNumber = "4012888888881881",
                CardType = 1,
                City = "Redmond",
                Country = "U.S.",
                Email = "admin@qq.com",
                Expiration = "12/20",
                Id = Guid.NewGuid().ToString(),
                LastName = "DemoLastName",
                Name = "DemoUser",
                PhoneNumber = "1234567890",
                UserName = "admin@qq.com",
                ZipCode = "98052",
                State = "WA",
                Street = "15703 NE 61st Ct",
                SecurityNumber = "535",
                NormalizedEmail = "admin@qq.com",
                NormalizedUserName = "admin@qq.com",
                SecurityStamp = Guid.NewGuid().ToString("D"),
            };

            user.PasswordHash = new PasswordHasher<ApplicationUser>().HashPassword(user, "admin");

            return new List<ApplicationUser>()
            {
                user
            };
        }
    }
}