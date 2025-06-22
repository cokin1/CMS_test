using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using AspNet.Identity.DataAccess; // IMPORTANT: Reference the types from the DLL

namespace KalikoCMS.Models // Make sure this matches your project's Models namespace
{
    // You can add profile data for the user by adding more properties to your ApplicationUser class, please visit https://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationUser : IdentityUser // Inherits from AspNet.Identity.DataAccess.IdentityUser
    {
        // Add any additional properties specific to your ApplicationUser here if needed.
        // For example:
        // public string FirstName { get; set; }
        // public string LastName { get; set; }

        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser, Guid> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }
    }

    public class ApplicationRole : IdentityRole // Inherits from AspNet.Identity.DataAccess.IdentityRole
    {
        // Add any additional properties specific to your ApplicationRole here if needed.
        // NOTE: These additional properties WILL NOT be persisted by the original AspNet.Identity.DataAccess.RoleStore
        // because it only understands AspNet.Identity.DataAccess.IdentityRole.
        // If you need to persist custom role properties, you will need a different data access layer or a custom solution.

        public ApplicationRole() : base() { }
        public ApplicationRole(string name) : base(name) { }
        public ApplicationRole(string name, Guid id) : base(name, id) { }
    }
}