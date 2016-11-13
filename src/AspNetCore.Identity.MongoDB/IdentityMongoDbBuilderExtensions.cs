using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCore.Identity.MongoDB
{
    /// <summary>
    /// Contains extension methods to <see cref="IdentityBuilder"/> for adding mongo db stores.
    /// </summary>
    public static class IdentityMongoDbBuilderExtensions
    {
        /// <summary>
        /// Adds an Entity Framework implementation of identity information stores.
        /// </summary>
        /// <typeparam name="TContext">The Entity Framework database context to use.</typeparam>
        /// <param name="builder">The <see cref="IdentityBuilder"/> instance this method extends.</param>
        /// <returns>The <see cref="IdentityBuilder"/> instance this method extends.</returns>
        public static IdentityBuilder AddMongoDbStores(this IdentityBuilder builder)
        {
            Type userStoreType;
            Type roleStoreType;

            userStoreType = typeof(UserStore<>).MakeGenericType(builder.UserType);
            roleStoreType = typeof(RoleStore<>).MakeGenericType(builder.RoleType);

            builder.Services.AddScoped(
                typeof(IUserStore<>).MakeGenericType(builder.UserType),
                userStoreType);
            builder.Services.AddScoped(
                typeof(IRoleStore<>).MakeGenericType(builder.RoleType),
                roleStoreType);

            return builder;
        }

    }
}
