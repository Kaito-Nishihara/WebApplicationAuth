using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using WebApplicationAuth.Entities;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace WebApplicationAuth.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class IdentityController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IOptionsMonitor<BearerTokenOptions> _bearerTokenOptions;
        
        private readonly LinkGenerator _linkGenerator;

        public IdentityController(UserManager<AppUser> userManager,
                                  SignInManager<AppUser> signInManager,
                                  IOptionsMonitor<BearerTokenOptions> bearerTokenOptions,
                                  
                                  LinkGenerator linkGenerator)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _bearerTokenOptions = bearerTokenOptions;
            
            _linkGenerator = linkGenerator;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest registration)
        {
            var email = registration.Email;
            if (string.IsNullOrEmpty(email) || !new EmailAddressAttribute().IsValid(email))
            {
                return BadRequest("Invalid email format.");
            }

            var user = new AppUser()
            {
                Name = email,
                Email = email,              
                UserName = email,
            };           

            var result = await _userManager.CreateAsync(user, registration.Password);
            if (!result.Succeeded) return BadRequest(result.Errors);

            await SendConfirmationEmailAsync(user, email);
            return Ok();
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest login, [FromQuery] bool? useCookies, [FromQuery] bool? useSessionCookies)
        {
            var isPersistent = (useCookies == true) && (useSessionCookies != true);
            _signInManager.AuthenticationScheme = (useCookies == true || useSessionCookies == true) ? IdentityConstants.ApplicationScheme : IdentityConstants.BearerScheme;

            var result = await _signInManager.PasswordSignInAsync(login.Email, login.Password, isPersistent, true);

            if (!result.Succeeded) return Unauthorized(result.ToString());

            return Ok("Login successful.");
        }

        [HttpGet("info")]
        public async Task<IActionResult> GetUserInfo()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            var infoResponse = await CreateInfoResponseAsync(user, _userManager);
            return Ok(infoResponse);
        }

        [HttpPost("info")]
        public async Task<IActionResult> UpdateUserInfo([FromBody] InfoRequest infoRequest)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return NotFound();
            }

            // Email validation
            if (!string.IsNullOrEmpty(infoRequest.NewEmail) && !new EmailAddressAttribute().IsValid(infoRequest.NewEmail))
            {
                return BadRequest("Invalid email format.");
            }

            // Password change handling
            if (!string.IsNullOrEmpty(infoRequest.NewPassword))
            {
                if (string.IsNullOrEmpty(infoRequest.OldPassword))
                {
                    return BadRequest("Old password is required to set a new password. Use /resetPassword if it is forgotten.");
                }

                var changePasswordResult = await _userManager.ChangePasswordAsync(user, infoRequest.OldPassword, infoRequest.NewPassword);
                if (!changePasswordResult.Succeeded)
                {
                    return BadRequest(changePasswordResult.Errors);
                }
            }

            // Email change handling
            if (!string.IsNullOrEmpty(infoRequest.NewEmail))
            {
                var currentEmail = await _userManager.GetEmailAsync(user);
                if (currentEmail != infoRequest.NewEmail)
                {
                    var code = await _userManager.GenerateChangeEmailTokenAsync(user, infoRequest.NewEmail);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                    var callbackUrl = Url.Action(nameof(ConfirmEmailChange), "Info", new { userId = await _userManager.GetUserIdAsync(user), code, newEmail = infoRequest.NewEmail }, Request.Scheme);

                    
                }
            }

            var updatedInfoResponse = await CreateInfoResponseAsync(user);
            return Ok(updatedInfoResponse);
        }

        // メール確認用エンドポイント
        [HttpGet("confirmEmailChange")]
        public async Task<IActionResult> ConfirmEmailChange(string userId, string code, string newEmail)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await _userManager.ChangeEmailAsync(user, newEmail, code);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok("Email changed successfully.");
        }

        [HttpGet("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string code)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return Unauthorized();

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await _userManager.ConfirmEmailAsync(user, code);

            if (!result.Succeeded) return Unauthorized(result.Errors);

            return Ok("Thank you for confirming your email.");
        }

        [HttpGet("roles")]
        [Authorize]
        public async Task<IActionResult> GetUserRoles()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Unauthorized();
            }

            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = roles.Select(role => new
            {
                Issuer = "LOCAL AUTHORITY",
                OriginalIssuer = "LOCAL AUTHORITY",
                Type = ClaimTypes.Role,
                Value = role,
                ValueType = "http://www.w3.org/2001/XMLSchema#string"
            });

            return Ok(roleClaims);
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout([FromBody] object empty)
        {
            if (empty != null)
            {
                await _signInManager.SignOutAsync();
                return Ok(new { message = "Logged out successfully" });
            }

            return Unauthorized(new { message = "Invalid request" });
        }

        private static async Task<InfoResponse> CreateInfoResponseAsync(AppUser user, UserManager<AppUser> userManager)
        {
            return new()
            {
                Email = await userManager.GetEmailAsync(user) ?? throw new NotSupportedException("Users must have an email."),
                IsEmailConfirmed = await userManager.IsEmailConfirmedAsync(user),
            };
        }

        private async Task SendConfirmationEmailAsync(AppUser user, string email)
        {
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            var userId = await _userManager.GetUserIdAsync(user);
            var confirmEmailUrl = _linkGenerator.GetUriByName(HttpContext, nameof(ConfirmEmail), new { userId, code });
            
        }

        private async Task<InfoResponse> CreateInfoResponseAsync(AppUser user)
        {
            return new InfoResponse
            {
                Email = await _userManager.GetEmailAsync(user) ?? throw new InvalidOperationException("User must have an email."),
                IsEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user)
            };
        }
    }
}
