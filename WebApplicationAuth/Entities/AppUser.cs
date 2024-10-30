using Microsoft.AspNetCore.Identity;

namespace WebApplicationAuth.Entities
{
#nullable disable
    public class AppUser: IdentityUser<int>
    {
        public string Name {  get; set; }

        public ICollection<AppUserRole> AppUserRoles { get; set; }        
    }
}
