using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using WebApplicationAuth.Entities;

namespace WebApplicationAuth.Controllers.Identity
{
    public class CustomRoleStore : RoleStoreBase<AppRole, int, AppUserRole, IdentityRoleClaim<int>>
    {
        private readonly IdentityErrorDescriber _describer;
        private readonly AppDbContext _context;

        public CustomRoleStore(IdentityErrorDescriber describer, AppDbContext context) : base(describer)
        {
            _describer = describer;
            _context = context;
        }

        /// <summary>
        /// ロール作成
        /// </summary>
        /// <param name="role"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public override async Task<IdentityResult> CreateAsync(AppRole role, CancellationToken cancellationToken = new CancellationToken())
        {
            _context.AppRoles.Add(role);
            _context.SaveChanges();

            return await Task.FromResult(IdentityResult.Success);
        }

        public override Task<IdentityResult> UpdateAsync(AppRole role, CancellationToken cancellationToken = new CancellationToken())
            => throw new NotImplementedException();

        public override Task<IdentityResult> DeleteAsync(AppRole role, CancellationToken cancellationToken = new CancellationToken())
            => throw new NotImplementedException();

        /// <summary>
        /// IDによるロール検索
        /// </summary>
        /// <param name="id"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        public override async Task<AppRole?> FindByIdAsync(string id, CancellationToken cancellationToken = new CancellationToken())
        {

            var role = _context.AppRoles.FirstOrDefault(e => e.Id == Convert.ToInt32(id));

            if (role == null)
            {
                return await Task.FromResult<AppRole>(null!);
            }

            return await Task.FromResult(role);
        }

        public override async Task<AppRole?> FindByNameAsync(string normalizedName, CancellationToken cancellationToken = new CancellationToken())
        {

            var role = _context.AppRoles.FirstOrDefault(e => e.Name == normalizedName);

            if (role == null)
            {
                return await Task.FromResult<AppRole>(null!);
            }

            return await Task.FromResult(role);
        }

        public override Task<IList<Claim>> GetClaimsAsync(AppRole role, CancellationToken cancellationToken = new CancellationToken())
        {
            //IList<Claim> claims = new List<Claim>();
            //// Retrieve the claims associated with the role from your data store
            //// and add them to the claims list
            //var roleClaims = await _context.RoleClaims
            //    .Where(c => c.RoleId == role.Id)
            //    .ToListAsync(cancellationToken);

            //foreach (var roleClaim in roleClaims)
            //{
            //    claims.Add(new Claim(roleClaim.ClaimType, roleClaim.ClaimValue));
            //}

            //return claims;
            IList<Claim> claims = Array.Empty<Claim>().ToList();
            return Task.FromResult(claims);
        }

        public override Task AddClaimAsync(AppRole role, Claim claim, CancellationToken cancellationToken = new CancellationToken())
            => throw new NotImplementedException();

        public override Task RemoveClaimAsync(AppRole role, Claim claim, CancellationToken cancellationToken = new CancellationToken())
            => throw new NotImplementedException();

        public override IQueryable<AppRole> Roles
            => throw new NotImplementedException();
    }
}
