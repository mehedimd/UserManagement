﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
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
        private readonly IMemoryCache _cache;
        private const string UserListCacheKey = "UserListCache";
        public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, IConfiguration config, IMemoryCache cache)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = config;
            _cache = cache;
        }
        #endregion

        #region Register
        [HttpPost("register")]
        [AllowAnonymous]
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
        [AllowAnonymous]
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
            user.RefreshTokenExpiry = DateTime.Now.AddDays(7);

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
                    expires: DateTime.Now.AddMinutes(30),
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

        #region Get Users
        //[Authorize]
        //[HttpGet("users")]
        //public async Task<IActionResult> GetUsers()
        //{
        //    try
        //    {
        //        var users = await _userManager.Users.Select(u => new
        //        {
        //            u.Id,
        //            u.Name,
        //            u.UserName,
        //            u.Email,
        //            u.DateOfBirth,
        //            u.Designation
        //        }).ToListAsync();

        //        return Ok(users);
        //    }
        //    catch (Exception ex)
        //    {
        //        return StatusCode(500, new { message = "An error occurred while fetching users.", error = ex.Message });
        //    }
        //}

        // -- Implement 
        [Authorize]
        [HttpGet("users")]
        public async Task<IActionResult> GetUsers()
        {
            try
            {
                if (!_cache.TryGetValue(UserListCacheKey, out List<object>? users))
                {
                    users = await _userManager.Users.Select(u => new
                    {
                        u.Id,
                        u.Name,
                        u.UserName,
                        u.Email,
                        u.DateOfBirth,
                        u.Designation
                    }).Cast<object>().ToListAsync();

                    var cacheOptions = new MemoryCacheEntryOptions().SetSlidingExpiration(TimeSpan.FromMinutes(2));

                    _cache.Set(UserListCacheKey, users, cacheOptions);
                }

                return Ok(users);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while fetching users.", error = ex.Message });
            }
        }
        #endregion

        #region Update User
        [HttpPut("user/update/{id}")]
        [Authorize]
        public async Task<IActionResult> UpdateUser(string id, [FromBody] UpdateUserVM vm)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            try
            {
                var user = await _userManager.FindByIdAsync(id);
                if (user == null) return NotFound(new { message = "User not found!" });

                // Update user properties
                user.Name = vm.Name;
                user.Email = vm.Email;
                user.Designation = vm.Designation;

                // Update  user in the database
                var result = await _userManager.UpdateAsync(user);
                if (!result.Succeeded) return BadRequest(new { message = "Failed to update user.", errors = result.Errors });

                return Ok(new { message = "User updated successfully!" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while updating the user.", error = ex.Message });
            }
        }
        #endregion

        #region Delete User
        [HttpDelete("user/delete/{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                    return NotFound(new { message = "User not found!" });

                var result = await _userManager.DeleteAsync(user);
                if (!result.Succeeded)
                    return BadRequest(new { message = "Failed to delete user!", errors = result.Errors });

                return Ok(new { message = "User deleted successfully!" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while deleting the user.", error = ex.Message });
            }
        }

        #endregion

    }
}
