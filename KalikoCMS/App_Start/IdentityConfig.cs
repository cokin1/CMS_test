using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;

// Using statements for your custom Identity components from the *DLL*
using AspNet.Identity.DataAccess; // For IdentityUser, IdentityRole
using AspNet.Identity.DataAccess.Data; // For DataContext
// IMPORTANT: Ensure you have a project reference to AspNet.Identity.DataAccess.dll

// Using statement for your application's custom Identity models
using KalikoCMS.Models; // Make sure this matches your project's Models namespace

namespace KalikoCMS // Make sure this matches your project's root namespace
{
    // --- ApplicationUserManager ---
    public class ApplicationUserManager : UserManager<ApplicationUser, Guid>
    {
        public ApplicationUserManager(IUserStore<ApplicationUser, Guid> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context)
        {
            // IMPORTANT: Since DataContext.SynchronizeSchema() is 'internal static'
            // and you don't have access to modify the AspNet.Identity.DataAccess project,
            // you cannot directly call it here.
            // This means automatic database schema synchronization will NOT happen via this code path.
            // DataContext.SynchronizeSchema(); // <-- COMMENTED OUT: Cannot access due to 'internal' access modifier

            var dataContext = new DataContext(); // Create a new instance of your DataContext

            // Use the custom ApplicationUserStore adapter
            var manager = new ApplicationUserManager(new ApplicationUserStore(dataContext));

            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<ApplicationUser, Guid>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                // These properties were causing the CS0117 error as your PasswordValidator
                // type (or its resolved version) might not have them.
                // If you require these password complexities, you will need to implement a custom
                // PasswordValidator or investigate your Identity NuGet package setup further.
                // RequireNonAlphanumeric = true,
                // RequireDigit = true,
                // RequireLowercase = true,
                // RequireUppercase = true,
            };

            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = true;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            manager.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<ApplicationUser, Guid>
            {
                MessageFormat = "Your security code is {0}"
            });
            manager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<ApplicationUser, Guid>
            {
                Subject = "Security Code",
                BodyFormat = "Your security code is {0}"
            });

            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider =
                    new DataProtectorTokenProvider<ApplicationUser, Guid>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }

    // --- ApplicationRoleManager ---
    public class ApplicationRoleManager : RoleManager<ApplicationRole, Guid>
    {
        public ApplicationRoleManager(IRoleStore<ApplicationRole, Guid> roleStore)
            : base(roleStore)
        {
        }

        public static ApplicationRoleManager Create(IdentityFactoryOptions<ApplicationRoleManager> options, IOwinContext context)
        {
            // IMPORTANT: See notes above for DataContext.SynchronizeSchema()
            // DataContext.SynchronizeSchema(); // <-- COMMENTED OUT: Cannot access due to 'internal' access modifier

            var dataContext = new DataContext();
            // Use the custom ApplicationRoleStore adapter
            return new ApplicationRoleManager(new ApplicationRoleStore(dataContext));
        }
    }

    // --- ApplicationSignInManager ---
    public class ApplicationSignInManager : SignInManager<ApplicationUser, Guid>
    {
        public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }

        public override Task<ClaimsIdentity> CreateUserIdentityAsync(ApplicationUser user)
        {
            return user.GenerateUserIdentityAsync((ApplicationUserManager)UserManager);
        }

        public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }
    }

    // --- ApplicationUserStore Adapter ---
    // This adapter class allows UserManager<ApplicationUser> to work with
    // the non-generic AspNet.Identity.DataAccess.UserStore.
    // It translates calls between ApplicationUser and IdentityUser.
    public class ApplicationUserStore :
        IUserLoginStore<ApplicationUser, Guid>,
        IUserClaimStore<ApplicationUser, Guid>,
        IUserRoleStore<ApplicationUser, Guid>,
        IUserPasswordStore<ApplicationUser, Guid>,
        IUserSecurityStampStore<ApplicationUser, Guid>,
        IQueryableUserStore<ApplicationUser, Guid>,
        IUserTwoFactorStore<ApplicationUser, Guid>,
        IUserLockoutStore<ApplicationUser, Guid>,
        IDisposable
    {
        private readonly AspNet.Identity.DataAccess.UserStore _innerStore;

        public ApplicationUserStore(DataContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            _innerStore = new AspNet.Identity.DataAccess.UserStore(context);
        }

        // Helper method to convert IdentityUser to ApplicationUser
        // This is crucial because you cannot directly cast a base class instance to a derived class.
        private ApplicationUser ConvertToApplicationUser(AspNet.Identity.DataAccess.IdentityUser identityUser)
        {
            if (identityUser == null)
                return null;

            // This assumes ApplicationUser *only* adds properties if needed, and IdentityUser
            // has all the core properties like Id, UserName, PasswordHash, SecurityStamp, etc.
            // If ApplicationUser adds *new* properties that need to be populated from the DB,
            // this conversion needs to be more complex, potentially involving database calls
            // or modifications to AspNet.Identity.DataAccess (which you cannot do).
            // For now, we assume ApplicationUser is just a "stronger typed" IdentityUser.

            // Common properties from IdentityUser to ApplicationUser:
            var appUser = new ApplicationUser
            {
                Id = identityUser.Id,
                UserName = identityUser.UserName,
                Email = identityUser.Email, // Assuming IdentityUser has Email, otherwise it's null
                EmailConfirmed = identityUser.EmailConfirmed,
                PasswordHash = identityUser.PasswordHash,
                SecurityStamp = identityUser.SecurityStamp,
                PhoneNumber = identityUser.PhoneNumber,
                PhoneNumberConfirmed = identityUser.PhoneNumberConfirmed,
                TwoFactorEnabled = identityUser.TwoFactorEnabled,
                LockoutEndDateUtc = identityUser.LockoutEndDateUtc,
                LockoutEnabled = identityUser.LockoutEnabled,
                AccessFailedCount = identityUser.AccessFailedCount
            };
            return appUser;
        }

        // IQueryableUserStore property:
        // You cannot directly cast IQueryable<IdentityUser> to IQueryable<ApplicationUser>.
        // This property needs to project the IdentityUser objects into ApplicationUser objects.
        // This can be computationally expensive if many users are queried and not filtered first.
        public IQueryable<ApplicationUser> Users => _innerStore.Users.Select(u => ConvertToApplicationUser(u));


        // --- IUserStore methods ---
        // For Create/Update/Delete, you pass the ApplicationUser to the inner store,
        // which accepts the base IdentityUser type.
        public async Task CreateAsync(ApplicationUser user) => await _innerStore.CreateAsync(user);
        public async Task UpdateAsync(ApplicationUser user) => await _innerStore.UpdateAsync(user);
        public async Task DeleteAsync(ApplicationUser user) => await _innerStore.DeleteAsync(user);

        // For Find methods, you need to convert the returned IdentityUser to ApplicationUser
        public async Task<ApplicationUser> FindByIdAsync(Guid userId) => ConvertToApplicationUser(await _innerStore.FindByIdAsync(userId));
        public async Task<ApplicationUser> FindByNameAsync(string userName) => ConvertToApplicationUser(await _innerStore.FindByNameAsync(userName));


        // --- IUserPasswordStore methods ---
        public async Task SetPasswordHashAsync(ApplicationUser user, string passwordHash) => await _innerStore.SetPasswordHashAsync(user, passwordHash);
        public async Task<string> GetPasswordHashAsync(ApplicationUser user) => await _innerStore.GetPasswordHashAsync(user);
        public async Task<bool> HasPasswordAsync(ApplicationUser user) => await _innerStore.HasPasswordAsync(user);

        // --- IUserSecurityStampStore methods ---
        public async Task SetSecurityStampAsync(ApplicationUser user, string stamp) => await _innerStore.SetSecurityStampAsync(user, stamp);
        public async Task<string> GetSecurityStampAsync(ApplicationUser user) => await _innerStore.GetSecurityStampAsync(user);

        // --- IUserRoleStore methods ---
        public async Task AddToRoleAsync(ApplicationUser user, string roleName) => await _innerStore.AddToRoleAsync(user, roleName);
        public async Task RemoveFromRoleAsync(ApplicationUser user, string roleName) => await _innerStore.RemoveFromRoleAsync(user, roleName);
        public async Task<IList<string>> GetRolesAsync(ApplicationUser user) => await _innerStore.GetRolesAsync(user);
        public async Task<bool> IsInRoleAsync(ApplicationUser user, string roleName) => await _innerStore.IsInRoleAsync(user, roleName);

        // --- IUserLoginStore methods ---
        public async Task AddLoginAsync(ApplicationUser user, UserLoginInfo login) => await _innerStore.AddLoginAsync(user, login);
        public async Task RemoveLoginAsync(ApplicationUser user, UserLoginInfo login) => await _innerStore.RemoveLoginAsync(user, login);
        public async Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user) => await _innerStore.GetLoginsAsync(user);
        // For FindAsync(UserLoginInfo login), you need to convert
        public async Task<ApplicationUser> FindAsync(UserLoginInfo login) => ConvertToApplicationUser(await _innerStore.FindAsync(login));

        // --- IUserClaimStore methods ---
        public async Task AddClaimAsync(ApplicationUser user, Claim claim) => await _innerStore.AddClaimAsync(user, claim);
        public async Task RemoveClaimAsync(ApplicationUser user, Claim claim) => await _innerStore.RemoveClaimAsync(user, claim);
        public async Task<IList<Claim>> GetClaimsAsync(ApplicationUser user) => await _innerStore.GetClaimsAsync(user);

        // --- IUserTwoFactorStore methods ---
        public async Task SetTwoFactorEnabledAsync(ApplicationUser user, bool enabled) => await _innerStore.SetTwoFactorEnabledAsync(user, enabled);
        public async Task<bool> GetTwoFactorEnabledAsync(ApplicationUser user) => await _innerStore.GetTwoFactorEnabledAsync(user);

        // --- IUserLockoutStore methods ---
        public async Task<DateTimeOffset> GetLockoutEndDateAsync(ApplicationUser user) => await _innerStore.GetLockoutEndDateAsync(user);
        public async Task SetLockoutEndDateAsync(ApplicationUser user, DateTimeOffset lockoutEnd) => await _innerStore.SetLockoutEndDateAsync(user, lockoutEnd);
        public async Task<int> IncrementAccessFailedCountAsync(ApplicationUser user) => await _innerStore.IncrementAccessFailedCountAsync(user);
        public async Task ResetAccessFailedCountAsync(ApplicationUser user) => await _innerStore.ResetAccessFailedCountAsync(user);
        public async Task<int> GetAccessFailedCountAsync(ApplicationUser user) => await _innerStore.GetAccessFailedCountAsync(user);
        public async Task SetLockoutEnabledAsync(ApplicationUser user, bool enabled) => await _innerStore.SetLockoutEnabledAsync(user, enabled);
        public async Task<bool> GetLockoutEnabledAsync(ApplicationUser user) => await _innerStore.GetLockoutEnabledAsync(user);

        public void Dispose()
        {
            _innerStore.Dispose();
        }
    }

    // --- ApplicationRoleStore Adapter ---
    public class ApplicationRoleStore :
        IRoleStore<ApplicationRole, Guid>,
        IQueryableRoleStore<ApplicationRole, Guid>,
        IDisposable
    {
        private readonly AspNet.Identity.DataAccess.RoleStore _innerStore;

        public ApplicationRoleStore(DataContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            _innerStore = new AspNet.Identity.DataAccess.RoleStore(context);
        }

        // You need a similar conversion for ApplicationRole if the inner store returns IdentityRole
        private ApplicationRole ConvertToApplicationRole(AspNet.Identity.DataAccess.IdentityRole identityRole)
        {
            if (identityRole == null)
                return null;

            return new ApplicationRole
            {
                Id = identityRole.Id,
                Name = identityRole.Name
            };
        }

        public IQueryable<ApplicationRole> Roles => _innerStore.Roles.Select(r => ConvertToApplicationRole(r));

        public async Task CreateAsync(ApplicationRole role) => await _innerStore.CreateAsync(role);
        public async Task UpdateAsync(ApplicationRole role) => await _innerStore.UpdateAsync(role);
        public async Task DeleteAsync(ApplicationRole role) => await _innerStore.DeleteAsync(role);
        public async Task<ApplicationRole> FindByIdAsync(Guid roleId) => ConvertToApplicationRole(await _innerStore.FindByIdAsync(roleId));
        public async Task<ApplicationRole> FindByNameAsync(string roleName) => ConvertToApplicationRole(await _innerStore.FindByNameAsync(roleName));

        public void Dispose()
        {
            _innerStore.Dispose();
        }
    }
}