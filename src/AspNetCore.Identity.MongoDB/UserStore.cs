using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using MongoDB.Driver;
using Microsoft.Extensions.Logging;
using MongoDB.Driver.Core.Misc;
using System.ComponentModel;
using System.Security.Claims;

namespace AspNetCore.Identity.MongoDB
{
    public class UserStore<TUser, TKey> :
        IUserLoginStore<TUser>,
        IUserClaimStore<TUser>,
        IUserRoleStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,
        IUserEmailStore<TUser>,
        IUserLockoutStore<TUser>,
        IUserPhoneNumberStore<TUser>,
        IUserTwoFactorStore<TUser>,
        IUserAuthenticationTokenStore<TUser>,
        IQueryableUserStore<TUser>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
    {
        private bool _disposed;

        public UserStore(IMongoDatabase mongoDatabase, IdentityErrorDescriber describer = null)
        {
            Ensure.IsNotNull(mongoDatabase, nameof(mongoDatabase));
            ErrorDescriber = describer ?? new IdentityErrorDescriber();
            UsersCollection = mongoDatabase.GetCollection<TUser>("Users");
        }

        /// <summary>
        /// Gets the database context for this store.
        /// </summary>
        protected IMongoCollection<TUser> UsersCollection { get; private set; }

        /// <summary>
        /// Gets or sets the <see cref="IdentityErrorDescriber"/> for any error that occurred with the current operation.
        /// </summary>
        protected IdentityErrorDescriber ErrorDescriber { get; set; }

        #region IUserStore
        public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            await UsersCollection.InsertOneAsync(user, null, cancellationToken);

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            var filter = Builders<TUser>.Filter.Eq(u => u.Id, user.Id);

            await UsersCollection.DeleteOneAsync(filter, cancellationToken);

            return IdentityResult.Success;
        }

        public async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var convertedId = ConvertIdFromString(userId);

            var filter = Builders<TUser>.Filter.Eq(u => u.Id, convertedId);

            return await UsersCollection.Find(filter).SingleOrDefaultAsync();
        }

        /// <summary>
        /// Converts the provided <paramref name="id"/> to a strongly typed key object.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey"/> representing the provided <paramref name="id"/>.</returns>
        protected virtual TKey ConvertIdFromString(string id)
        {
            if (id == null)
            {
                return default(TKey);
            }
            return (TKey)TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
        }

        public async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNullOrEmpty(normalizedUserName, nameof(normalizedUserName));

            var filter = Builders<TUser>.Filter.Eq(u => u.NormalizedUserName, normalizedUserName);

            return await UsersCollection.Find(filter).FirstOrDefaultAsync(cancellationToken);
        }

        public Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            return Task.FromResult(user.NormalizedUserName);
        }

        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            return Task.FromResult(ConvertIdToString(user.Id));
        }

        /// <summary>
        /// Converts the provided <paramref name="id"/> to its string representation.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An <see cref="string"/> representation of the provided <paramref name="id"/>.</returns>
        protected virtual string ConvertIdToString(TKey id)
        {
            if (object.Equals(id, default(TKey)))
            {
                return null;
            }
            return id.ToString();
        }

        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            return Task.FromResult(user.UserName);
        }

        public Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            user.NormalizedUserName = normalizedName;

            return Task.CompletedTask;
        }

        public Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            user.UserName = userName;
            return Task.CompletedTask;
        }

        public async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            var filter = Builders<TUser>.Filter.Eq(u => u.Id, user.Id);

            var replaceResult = await UsersCollection.ReplaceOneAsync(filter, user, new UpdateOptions { IsUpsert = false }, cancellationToken);

            return replaceResult.Success() ? IdentityResult.Success : IdentityResult.Failed();
        }
        #endregion

        #region IUserLoginStore
        public Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));
            Ensure.IsNotNull(login, nameof(login));

            user.Logins.Add(new IdentityUserLogin(login));

            return Task.CompletedTask;
        }

        public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNullOrEmpty(loginProvider, nameof(loginProvider));
            Ensure.IsNotNullOrEmpty(providerKey, nameof(providerKey));

            var filter = Builders<TUser>.Filter.ElemMatch(u => u.Logins,
                 Builders<IdentityUserLogin>.Filter.And(
                   Builders<IdentityUserLogin>.Filter.Eq(lg => lg.LoginProvider, loginProvider),
                   Builders<IdentityUserLogin>.Filter.Eq(lg => lg.ProviderKey, providerKey)
               ));

            return await UsersCollection.Find(filter).FirstOrDefaultAsync(cancellationToken);
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            var logins = from l in user.Logins
                         select new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName);
            return Task.FromResult<IList<UserLoginInfo>>(logins.ToList());
        }

        public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));
            Ensure.IsNotNullOrEmpty(loginProvider, nameof(loginProvider));
            Ensure.IsNotNullOrEmpty(providerKey, nameof(providerKey));

            var login = user.Logins.FirstOrDefault(ul => ul.LoginProvider == loginProvider && ul.ProviderKey == providerKey);
            if (login != null)
            {
                user.Logins.Remove(login);
            }

            return Task.CompletedTask;
        }
        #endregion

        #region IUserClaimStore
        public Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            var claims = from c in user.Claims
                         select c.ToClaim();
            return Task.FromResult<IList<Claim>>(claims.ToList());
        }

        public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            Ensure.IsNotNull(claims, nameof(claims));

            foreach (var claim in claims)
            {
                user.Claims.Add(new IdentityUserClaim(claim));
            }

            return Task.CompletedTask;
        }

        public Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));
            Ensure.IsNotNull(claim, nameof(claim));
            Ensure.IsNotNull(newClaim, nameof(newClaim));

            var matchedClaims = user.Claims.Where(uc => uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type);
            foreach (var matchedClaim in matchedClaims)
            {
                matchedClaim.ClaimValue = newClaim.Value;
                matchedClaim.ClaimType = newClaim.Type;
            }

            return Task.CompletedTask;
        }

        public Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));
            Ensure.IsNotNull(claims, nameof(claims));

            foreach (var claim in claims)
            {
                var matchedClaims = user.Claims.Where(uc => uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type).ToList();
                foreach (var c in matchedClaims)
                {
                    user.Claims.Remove(c);
                }
            }

            return Task.CompletedTask;
        }

        public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(claim, nameof(claim));

            var filter = Builders<TUser>.Filter.ElemMatch(u => u.Claims,
                 Builders<IdentityUserClaim>.Filter.And(
                   Builders<IdentityUserClaim>.Filter.Eq(lg => lg.ClaimType, claim.Type),
                   Builders<IdentityUserClaim>.Filter.Eq(lg => lg.ClaimValue, claim.Value)
               ));

            return await UsersCollection.Find(filter).ToListAsync(cancellationToken);
        }
        #endregion

        #region IUserRoleStore
        public Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));
            Ensure.IsNotNullOrEmpty(roleName, nameof(roleName));

            user.Roles.Add(roleName);

            return Task.CompletedTask;
        }

        public Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));
            Ensure.IsNotNullOrEmpty(roleName, nameof(roleName));

            user.Roles.Remove(roleName);

            return Task.CompletedTask;
        }

        public Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            return Task.FromResult<IList<string>>(user.Roles.ToList());
        }

        public Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));
            Ensure.IsNotNullOrEmpty(roleName, nameof(roleName));

            return Task.FromResult( user.Roles.Any(ur => ur == roleName));
        }

        public async Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNullOrEmpty(roleName, nameof(roleName));

            var filter = Builders<TUser>.Filter.ElemMatch(u => u.Roles, ur => ur == roleName);

            return await UsersCollection.Find(filter).ToListAsync(cancellationToken);
        }
        #endregion

        #region IUserPasswordStore
        public Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.PasswordHash = passwordHash;
            return Task.CompletedTask;
        }

        public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(user.PasswordHash != null);
        }
        #endregion

        #region IUserSecurityStampStore
        public Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.SecurityStamp = stamp;
            return Task.CompletedTask;
        }

        public Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            return Task.FromResult(user.SecurityStamp);
        }
        #endregion

        #region IUserEmailStore
        public Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.Email = email;
            return Task.CompletedTask;
        }

        public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            return Task.FromResult(user.EmailConfirmed);
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.EmailConfirmed = confirmed;
            return Task.CompletedTask;
        }

        public Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var filter = Builders<TUser>.Filter.Eq(u => u.NormalizedEmail, normalizedEmail);
            return UsersCollection.Find(filter).FirstOrDefaultAsync(cancellationToken);
        }

        public Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            return Task.FromResult(user.NormalizedEmail);
        }

        public Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.NormalizedEmail = normalizedEmail;
            return Task.CompletedTask;
        }
        #endregion

        #region IUserLockoutStore
        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            return Task.FromResult(user.LockoutEnd);
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.LockoutEnd = lockoutEnd;
            return Task.CompletedTask;
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.AccessFailedCount = 0;
            return Task.CompletedTask;
        }

        public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            return Task.FromResult(user.LockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.LockoutEnabled = enabled;
            return Task.CompletedTask;
        }
        #endregion

        #region IUserPhoneNumberStore
        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.PhoneNumber = phoneNumber;
            return Task.CompletedTask;
        }

        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.PhoneNumberConfirmed = confirmed;
            return Task.CompletedTask;
        }
        #endregion

        #region IUserTwoFactorStore
        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            user.TwoFactorEnabled = enabled;
            return Task.CompletedTask;
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(user, nameof(user));
            return Task.FromResult(user.TwoFactorEnabled);
        }
        #endregion

        #region IUserAuthenticationTokenStore
        public Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            var token = user.GetToken(loginProvider, name);
            if (token == null)
            {
                user.Tokens.Add(new IdentityUserToken(loginProvider, name, value));
            }
            else
            {
                token.Value = value;
            }

            return Task.CompletedTask;
        }

        public Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            var token = user.GetToken(loginProvider, name);
            if (token != null)
            {
                user.Tokens.Remove(token);
            }

            return Task.CompletedTask;
        }

        public Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(user, nameof(user));

            var token = user.GetToken(loginProvider, name);
            return Task.FromResult(token == null? null : token.Value);
        }
        #endregion

        #region IQueryableUserStore
        public IQueryable<TUser> Users
        {
            get
            {
                return UsersCollection.AsQueryable();
            }
        }
        #endregion

        #region Dispose
        /// <summary>
        /// Throws if this class has been disposed.
        /// </summary>
        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        /// <summary>
        /// Dispose the store
        /// </summary>
        public void Dispose()
        {
            _disposed = true;
        }
        #endregion

    }
}
