using Microsoft.EntityFrameworkCore;

namespace WebApplicationAuth.Entities
{
    public class AppDbContext:DbContext
    {
        public AppDbContext()
        {

        }

        public AppDbContext(DbContextOptions options) : base(options)
        {
        }

        public virtual DbSet<AppUser> AppUsers { get; set; }
        public virtual DbSet<AppRole> AppRoles { get; set; }
        public virtual DbSet<AppUserRole> AppUserRoles { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<AppUserRole>().HasKey(x => new { x.UserId, x.RoleId });
            base.OnModelCreating(modelBuilder);
        }
    }
}
