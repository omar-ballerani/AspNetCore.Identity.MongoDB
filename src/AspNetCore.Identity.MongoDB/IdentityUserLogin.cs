using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.Identity.MongoDB
{
    /// <summary>
    /// Represents a login and its associated provider for a user.
    /// </summary>
    /// <typeparam name="TKey">The type of the primary key of the user associated with this login.</typeparam>
    public class IdentityUserLogin
    {
        public IdentityUserLogin(UserLoginInfo userLoginInfo)
        {
            if (userLoginInfo == null)
            {
                throw new ArgumentNullException(nameof(userLoginInfo));
            }
            this.LoginProvider = userLoginInfo.LoginProvider;
            this.ProviderKey = userLoginInfo.ProviderKey;
            this.ProviderDisplayName = userLoginInfo.ProviderDisplayName;
        }
        /// <summary>
        /// Gets or sets the login provider for the login (e.g. facebook, google)
        /// </summary>
        public virtual string LoginProvider { get; set; }

        /// <summary>
        /// Gets or sets the unique provider identifier for this login.
        /// </summary>
        public virtual string ProviderKey { get; set; }

        /// <summary>
        /// Gets or sets the friendly name used in a UI for this login.
        /// </summary>
        public virtual string ProviderDisplayName { get; set; }

    }
}
