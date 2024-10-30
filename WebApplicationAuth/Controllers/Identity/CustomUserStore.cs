using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using WebApplicationAuth.Entities;

namespace WebApplicationAuth.Controllers.Identity
{
    public class CustomUserStore : UserStoreBase<AppUser, int, IdentityUserClaim<int>, IdentityUserLogin<int>, IdentityUserToken<int>>, IUserRoleStore<AppUser>
    {
        private readonly IdentityErrorDescriber _describer;
        private readonly AppDbContext _dbContext;
        private readonly ILookupNormalizer KeyNormalizer;
        private CancellationToken CancellationToken => CancellationToken.None;

        public CustomUserStore(IdentityErrorDescriber describer, AppDbContext dbContext, ILookupNormalizer keyNormalizer) : base(describer)
        {
            _describer = describer;
            _dbContext = dbContext;
            KeyNormalizer = keyNormalizer;

        }

        /// <summary>
        /// アカウント作成
        /// </summary>
        /// <param name="user"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> CreateAsync(AppUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            //Summary: アカウント認証テーブル登録処理
            _dbContext.AppUsers.Add(user);
            _dbContext.SaveChanges();

            return await Task.FromResult(IdentityResult.Success);
        }

        /// <summary>
        /// アカウント更新
        /// </summary>
        /// <param name="user"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> UpdateAsync(AppUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            _dbContext.Update(user);
            _dbContext.SaveChanges();

            return await Task.FromResult(IdentityResult.Success);
        }

        public override async Task<IdentityResult> DeleteAsync(AppUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            _dbContext.AppUsers.Remove(user);
            _dbContext.SaveChanges();
            return await Task.FromResult(IdentityResult.Success);
        }

        /// <summary>
        /// IDによるアカウント検索
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public override async Task<AppUser?> FindByIdAsync(string userId, CancellationToken cancellationToken = new CancellationToken())
        {
            var user = _dbContext.AppUsers
                .Include(e => e.AppUserRoles)
                .FirstOrDefault(e => e.Id == Convert.ToInt32(userId));

            if (user == null)
            {
                return await Task.FromResult<AppUser>(null!);
            }

            return await Task.FromResult(user);
        }

        /// <summary>
        /// 名前によるアカウント検索
        /// </summary>
        /// <param name="normalizedUserName"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public override async Task<AppUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = new CancellationToken())
        {

            var user = _dbContext.AppUsers.FirstOrDefault(e => e.NormalizedUserName == normalizedUserName);

            if (user == null)
            {
                return await Task.FromResult<AppUser>(null!);
            }

            return await Task.FromResult(user);
        }

        protected override Task<AppUser?> FindUserAsync(int userId, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        protected override Task<IdentityUserLogin<int>?> FindUserLoginAsync(int userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        protected override Task<IdentityUserLogin<int>?> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        public override async Task<IList<Claim>> GetClaimsAsync(AppUser user, CancellationToken cancellationToken = new CancellationToken())
        {
            return await Task.FromResult(Array.Empty<Claim>());
        }

        public override Task AddClaimsAsync(AppUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = new CancellationToken())
            => throw new NotImplementedException();

        public override Task ReplaceClaimAsync(AppUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = new CancellationToken())
            => throw new NotImplementedException();

        public override Task RemoveClaimsAsync(AppUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = new CancellationToken())
            => throw new NotImplementedException();

        public override Task<IList<AppUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = new CancellationToken())
            => throw new NotImplementedException();

        protected override async Task<IdentityUserToken<int>?> FindTokenAsync(AppUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            var AppUser = _dbContext.AppUsers.FirstOrDefault(e => e.Id == user.Id);
            if (AppUser is null)
            {
                return await Task.FromResult<IdentityUserToken<int>>(null!);
            }
            return await Task.FromResult(new IdentityUserToken<int>
            {
                UserId = AppUser.Id,
                LoginProvider = "Email",
                //LoginProvider = "AspNetUserStore",
                Name = "tokenName",
                Value = "None",
            });
        }

        protected override Task AddUserTokenAsync(IdentityUserToken<int> token)
            => throw new NotImplementedException();

        protected override Task RemoveUserTokenAsync(IdentityUserToken<int> token)
            => throw new NotImplementedException();

        public override IQueryable<AppUser> Users
            => throw new NotImplementedException();

        public override Task AddLoginAsync(AppUser user, UserLoginInfo login, CancellationToken cancellationToken = new CancellationToken())
            => throw new NotImplementedException();

        public override Task RemoveLoginAsync(AppUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = new CancellationToken())
            => throw new NotImplementedException();

        public override Task<IList<UserLoginInfo>> GetLoginsAsync(AppUser user, CancellationToken cancellationToken = new CancellationToken())
            => throw new NotImplementedException();

        public override async Task<AppUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = new CancellationToken())
        {
            var user = _dbContext.AppUsers.FirstOrDefault(e => e.NormalizedEmail == normalizedEmail);

            if (user == null)
            {
                return await Task.FromResult<AppUser>(null!);
            }

            return await Task.FromResult(user);
        }

        public async Task<AppUser?> FindByEmail(string email, int loginType)
        {
            if (email == null)
            {
                throw new ArgumentNullException(nameof(email));
            }

            email = NormalizeEmail(email);
            return await FindByEmailAsync(email, CancellationToken);
        }

        public virtual string NormalizeEmail(string email)
            => KeyNormalizer == null ? email : KeyNormalizer.NormalizeEmail(email);

        // for userrole
        public async Task AddToRoleAsync(AppUser user, string roleName, CancellationToken cancellationToken)
        {
            var role = _dbContext.AppRoles.FirstOrDefault(e => e.NormalizedName == roleName);

            if (role == null)
            {
                return;
            }

            var userRole = new AppUserRole { RoleId = role.Id, UserId = user.Id };

            // ユーザロールの登録
            await _dbContext.AppUserRoles.AddAsync(userRole);
            await _dbContext.SaveChangesAsync();

            return;
        }

        public Task<List<AppRole>> GetRolesAsync(AppUser user, CancellationToken cancellationToken)
        {
            var userRoleIds = _dbContext.AppUserRoles.Where(ur => ur.UserId == user.Id).Select(ur => ur.RoleId);

            var userRoles = _dbContext.AppRoles.Where(r => userRoleIds.Contains(r.Id)).ToList();

            return Task.FromResult(userRoles);
        }

        public Task GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
            => throw new NotImplementedException();

        public async Task RemoveFromRoleAsync(AppUser user, string roleName, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (string.IsNullOrEmpty(roleName))
            {
                throw new ArgumentException("Role name cannot be null or empty", nameof(roleName));
            }
            var userRoleIds = _dbContext.AppUserRoles.Where(ur => ur.UserId == user.Id);
            var userRole = userRoleIds.Where(ur => ur.AppRole.Name == roleName).FirstOrDefault();
            if (userRole is not null)
            {
                user.AppUserRoles.Remove(userRole);
                await _dbContext.SaveChangesAsync();
            }
        }

        public async Task RemoveFromRolesAsync(AppUser user, IEnumerable<string> roles, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (roles is null || !roles.Any())
            {
                throw new ArgumentException("Role name cannot be null or empty", nameof(roles));
            }
            foreach (var role in roles)
            {
                await RemoveFromRoleAsync(user, role, cancellationToken);
            }
        }

        Task<IList<string>> IUserRoleStore<AppUser>.GetRolesAsync(AppUser user, CancellationToken cancellationToken)
        {
            var userRoleIds = _dbContext.AppUserRoles.Where(ur => ur.UserId == user.Id).Select(ur => ur.RoleId);

            var userRoles = _dbContext.AppRoles.Where(r => userRoleIds.Contains(r.Id)).ToList();

            IList<string> roleNames = new List<string>();
            foreach (var role in userRoles)
            {
                roleNames.Add(role?.NormalizedName!);// or Name ?
            }

            return Task.FromResult(roleNames);
        }

        public async Task<bool> IsInRoleAsync(AppUser user, string roleName, CancellationToken cancellationToken)
        {
            var roles = await GetRolesAsync(user, cancellationToken);
            var roleNames = new List<string>();
            foreach (var role in roles)
            {
                roleNames.Add(role?.NormalizedName!);// or Name ?
            }
            return roleNames.Contains(roleName);
        }
        Task<IList<AppUser>> IUserRoleStore<AppUser>.GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

    }
}
