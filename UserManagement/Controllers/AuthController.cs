using Azure.Core;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using UserManagement.Models;
using UserManagement.Models.ViewModels;

namespace UserManagement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        #region Config
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public readonly IConfiguration _configuration;

        public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,RoleManager<IdentityRole> roleManager, IConfiguration config)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = config;
        }
        #endregion

        #region Register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterVM vm)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);


            try
            {
                // check if UserName already exists
                var existingUser = await _userManager.FindByNameAsync(vm.UserName);

                if (existingUser != null) return BadRequest(new { message = "Username already taken!" });

                var user = new ApplicationUser
                {
                    Name = vm.Name,
                    Email = vm.Email,
                    Designation = vm.Designation,
                    DateOfBirth = vm.DateOfBirth,
                    UserName = vm.UserName
                };

                var result = await _userManager.CreateAsync(user, vm.Password);

                if (!result.Succeeded) return BadRequest(result.Errors);

                // Assign role
                if (!string.IsNullOrEmpty(vm.Role))
                {
                    var roleExist = await _roleManager.RoleExistsAsync(vm.Role);
                    if (!roleExist) return BadRequest(new { message = "Role does not exist!" });

                    var addToRoleResult = await _userManager.AddToRoleAsync(user, vm.Role);
                    if (!addToRoleResult.Succeeded) return BadRequest(new { message = "Failed to assign role!" });
                }
                return Ok(new { message = "User registered successfully!" });
            }
            catch (Exception)
            {

                throw;
            }
        }
        #endregion

        #region Login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginVM vm)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);


            var user = await _userManager.FindByNameAsync(vm.UserName);
            if (user == null) return BadRequest(new { message = "Invalid username!" });

            var result = await _signInManager.CheckPasswordSignInAsync(user, vm.Password, false);

            if (!result.Succeeded) return BadRequest(new { message = "Invalid password!" });

            var accessToken = await GenerateAccessToken(user);
            var refreshToken = await GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);

            await _userManager.UpdateAsync(user);

            return Ok(new TokenVM
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }
        #endregion

        #region Refresh Token
        [HttpPost("refresh/token")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenVM vm)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.RefreshToken == vm.RefreshToken);

            if (user is null) return Unauthorized(new { message = "Invalid Token!" });
            else if (user.RefreshTokenExpiry < DateTime.UtcNow) return Unauthorized(new { message = "Expired refresh token!" });

            var newToken = await GenerateAccessToken(user);
            var newRefreshToken = await GenerateRefreshToken();

            // update refresh token in database
            user.RefreshToken = newRefreshToken;

            await _userManager.UpdateAsync(user);

            return Ok(new TokenVM
            {
                AccessToken = newToken,
                RefreshToken = newRefreshToken
            });
        }
        #endregion

        #region Generate Access Token
        private async Task<string> GenerateAccessToken(ApplicationUser user)
        {
            try
            {
                var secretKey = _configuration["Jwt:Secret"] ?? throw new InvalidOperationException("JWT secret key is missing!");

                SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
                SigningCredentials cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName),
                };

                // add roles in claim
                var roles = await _userManager.GetRolesAsync(user);
                claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

                var tokenOptions = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(1),
                    signingCredentials: cred
                    );

                string tokenString = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

                return tokenString;
            }
            catch (Exception)
            {

                throw;
            }
        }
        #endregion

        #region Generate Refresh Token
        private async Task<string> GenerateRefreshToken()
        {
            try
            {
                var randomNumber = new byte[32];
                await Task.Run(() =>
                {
                    using (var randomNumberGenerator = RandomNumberGenerator.Create())
                    {
                        randomNumberGenerator.GetBytes(randomNumber);
                    }
                });
                return Convert.ToBase64String(randomNumber);
            }
            catch (Exception)
            {

                throw;
            }
        }
        #endregion

        #region Get Roles
        [HttpGet("roles")]
        public async Task<IActionResult> GetRoles()
        {
            try
            {
                var roles = await _roleManager.Roles.ToListAsync();

                if (roles.Any())
                {
                    return Ok(roles.Select(r => r.Name)); // Return only the role names
                }
                else
                {
                    return NotFound(new { message = "No roles found." });
                }
            }
            catch (Exception ex)
            {
                // Log the exception
                return StatusCode(500, new { message = "An error occurred while processing your request.", details = ex.Message });
            }
        }

        #endregion
    }
}
