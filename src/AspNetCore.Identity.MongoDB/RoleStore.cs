using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using MongoDB.Driver.Core.Misc;
using MongoDB.Driver;
using System.ComponentModel;
using System.Security.Claims;

namespace AspNetCore.Identity.MongoDB
{
    public class RoleStore<TRole> :
        IRoleClaimStore<TRole>,
        IQueryableRoleStore<TRole>
        where TRole: IdentityRole
        
    {
        private bool _disposed = false;

        public RoleStore(IMongoDatabase mongoDatabase, IdentityErrorDescriber describer = null)
        {
            Ensure.IsNotNull(mongoDatabase, nameof(mongoDatabase));
            ErrorDescriber = describer ?? new IdentityErrorDescriber();
            RolesCollection = mongoDatabase.GetCollection<TRole>("Roles");
        }

        /// <summary>
        /// Gets the database context for this store.
        /// </summary>
        protected IMongoCollection<TRole> RolesCollection { get; private set; }

        /// <summary>
        /// Gets or sets the <see cref="IdentityErrorDescriber"/> for any error that occurred with the current operation.
        /// </summary>
        protected IdentityErrorDescriber ErrorDescriber { get; set; }

        #region IRoleStore
        public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(role, nameof(role));

            await RolesCollection.InsertOneAsync(role, null, cancellationToken);

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            Ensure.IsNotNull(role, nameof(role));
            var filter = Builders<TRole>.Filter.Eq(r => r.Id, role.Id);
            var replaceResult = await RolesCollection.ReplaceOneAsync(filter, role, new UpdateOptions { IsUpsert = false }, cancellationToken);

            return replaceResult.Success()? IdentityResult.Success : IdentityResult.Failed();
        }

        public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(role, nameof(role));

            var filter = Builders<TRole>.Filter.Eq(r => r.Id, role.Id);
            var deleteResult = await RolesCollection.DeleteOneAsync(filter, cancellationToken);
            return deleteResult.Success() ? IdentityResult.Success : IdentityResult.Failed();
        }

        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(role, nameof(role));

            return Task.FromResult(role.Id.ToString());
        }

        public Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(role, nameof(role));

            return Task.FromResult(role.Name);
        }

        public Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(role, nameof(role));

            role.Name = roleName;
            return Task.CompletedTask;
        }

        public Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(role, nameof(role));

            return Task.FromResult(role.NormalizedName);
        }

        public Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            Ensure.IsNotNull(role, nameof(role));

            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        public Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            ObjectId typedRoleId;
            if (!ObjectId.TryParse(roleId, out typedRoleId))
            {
                throw new ArgumentOutOfRangeException("unable to parse roleId");
            }

            var filter = Builders<TRole>.Filter.Eq(r => r.Id, typedRoleId);
            return RolesCollection.Find(filter).FirstOrDefaultAsync(cancellationToken); 
        }

        public Task<TRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var filter = Builders<TRole>.Filter.Eq(r => r.NormalizedName, normalizedRoleName);
            return RolesCollection.Find(filter).FirstOrDefaultAsync(cancellationToken);
        }

        #endregion

        #region IRoleClaimStore
        public Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();

            Ensure.IsNotNull(role, nameof(role));

            return Task.FromResult<IList<Claim>>( (role.Claims.Select(rc => rc.ToClaim())).ToList());
        }

        public Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            Ensure.IsNotNull(role, nameof(role));
            Ensure.IsNotNull(claim, nameof(claim));
            role.Claims.Add(new IdentityRoleClaim(claim));
            return Task.CompletedTask;
        }

        public Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            var claims = role.Claims.Where(rc => rc.ClaimValue == claim.Value && rc.ClaimType == claim.Type).ToList();
            foreach (var c in claims)
            {
                role.Claims.Remove(c);
            }
            return Task.CompletedTask;
        }
        #endregion

        #region IQueryableRoleStore
        public IQueryable<TRole> Roles
        {
            get
            {
                return RolesCollection.AsQueryable();
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
        /// Dispose the stores
        /// </summary>
        public void Dispose()
        {
            _disposed = true;
        }
        #endregion
    }
}
