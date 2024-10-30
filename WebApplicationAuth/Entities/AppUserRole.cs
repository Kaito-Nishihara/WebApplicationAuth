using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebApplicationAuth.Entities
{
#nullable disable
    public class AppUserRole:IdentityUserRole<int>
    {
        [Required,ForeignKey(nameof(AppUser))]
        public override int UserId { get ; set ; }

        [Required, ForeignKey(nameof(AppRole))]
        public override int RoleId { get; set; }

        public AppRole AppRole { get; set; } 
        public AppUser AppUser { get; set; }
    }
}
