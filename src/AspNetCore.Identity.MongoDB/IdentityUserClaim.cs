using System;
using System.Security.Claims;

namespace AspNetCore.Identity.MongoDB
{
    /// <summary>
    /// Represents a claim that a user possesses. 
    /// </summary>
    /// <typeparam name="TKey">The type used for the primary key for this user that possesses this claim.</typeparam>
    public class IdentityUserClaim
    {
        public IdentityUserClaim(Claim claim): this()
        {
            this.ClaimType = claim.Type;
            this.ClaimValue = claim.Value;
        }

        /// <summary>
        /// Default ctor - Initialize the istance
        /// </summary>
        public IdentityUserClaim()
        {
            this.Id = Guid.NewGuid().ToString();
        }
        /// <summary>
        /// Gets or sets the identifier for this user claim.
        /// </summary>
        public virtual string Id { get; set; }

        /// <summary>
        /// Gets or sets the claim type for this claim.
        /// </summary>
        public virtual string ClaimType { get; set; }

        /// <summary>
        /// Gets or sets the claim value for this claim.
        /// </summary>
        public virtual string ClaimValue { get; set; }

        /// <summary>
        /// Converts the entity into a Claim instance.
        /// </summary>
        /// <returns></returns>
        public virtual Claim ToClaim()
        {
            return new Claim(ClaimType, ClaimValue);
        }

    }
}
