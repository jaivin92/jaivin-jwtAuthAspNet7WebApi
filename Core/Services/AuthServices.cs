using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using jwtAuthAspNet7WebApi.Core.Dtos;
using jwtAuthAspNet7WebApi.Core.Entities;
using jwtAuthAspNet7WebApi.Core.Interfaces;
using jwtAuthAspNet7WebApi.Core.OtherObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace jwtAuthAspNet7WebApi.Core.Services
{
    public class AuthServices : IAuthServices
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthServices(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<AuthServicesResponseDto> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);

            if (user is null)
                return new AuthServicesResponseDto()
                {
                    IsSuceed = false,
                    Message = "Invalid Credentials"
                };

            var isPasswordCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);

            if (!isPasswordCorrect)
                return new AuthServicesResponseDto()
                {
                    IsSuceed = false,
                    Message = "Invalid Credentials"
                };

            var userRoles = await _userManager.GetRolesAsync(user);
            //generate 256 token and data response convert in byt code to json  jwt toek online
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString()),
                new Claim("FirstName", user.FirstName),
                new Claim("LastName", user.LastName),
            };

            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }

            var token = GenerateNewJsonWebToken(authClaims);

            return new AuthServicesResponseDto()
            {
                IsSuceed = true,
                Message = token
            };
        }

        private string GenerateNewJsonWebToken(List<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]));

            var tokenObject = new JwtSecurityToken(
                    issuer: _configuration["Jwt:ValidIssuer"],
                    audience: _configuration["Jwt:ValidAudience"],
                    expires: DateTime.Now.AddHours(1),
                    claims: claims,
                    signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
                );

            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

            return token;
        }

        public async Task<AuthServicesResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return new AuthServicesResponseDto()
                {
                    IsSuceed = false,
                    Message= "Invalid User!!!!"
                };

            await _userManager.AddToRoleAsync(user, StaticUserRole.ADMIN);

            return new AuthServicesResponseDto()
            {
                IsSuceed = true,
                Message = "User Is Now Admin"
            };
        }

        public async Task<AuthServicesResponseDto> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);

            if (user is null)
                return new AuthServicesResponseDto()
                {
                    IsSuceed = false,
                    Message = "Invalid User!!!!"
                };

            await _userManager.AddToRoleAsync(user, StaticUserRole.OWNER);

            return new AuthServicesResponseDto()
            {
                IsSuceed = true,
                Message = "User Is Now Owner"
            };
        }

        public async Task<AuthServicesResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            var isExistsUser = await _userManager.FindByNameAsync(registerDto.UserName);

            if (isExistsUser != null)
                return new AuthServicesResponseDto()
                {
                    IsSuceed = false,
                    Message = "User Already Exists"
                };

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                Email = registerDto.Email,
                UserName = registerDto.UserName,
                SecurityStamp = Guid.NewGuid().ToString(),
            };


            var createResult = await _userManager.CreateAsync(newUser, registerDto.Password);

            if (!createResult.Succeeded)
            {
                var errorString = "User Creation Fail Because : ";
                foreach (var error in createResult.Errors)
                {
                    errorString += " # " + error.Description;
                }
                return new AuthServicesResponseDto()
                {
                    IsSuceed = false,
                    Message = errorString
                };
            }

            //Add a Default User Role  to all User

            await _userManager.AddToRoleAsync(newUser, StaticUserRole.USER);

            return new AuthServicesResponseDto()
            {
                IsSuceed = true,
                Message = "User Create Sucessfully"
            };
        }

        public async Task<AuthServicesResponseDto> SeedRolesAsync()
        {
            bool isOwnerRoleExists = await _roleManager.RoleExistsAsync(StaticUserRole.OWNER);
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRole.ADMIN);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRole.USER);

            if (isOwnerRoleExists && isAdminRoleExists && isUserRoleExists)
                return new AuthServicesResponseDto()
                {
                    IsSuceed = true,
                    Message = "Roles Seeding is Already Done"
                };


            await _roleManager.CreateAsync(new IdentityRole(StaticUserRole.USER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRole.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRole.OWNER));

            return new AuthServicesResponseDto()
            {
                IsSuceed = true,
                Message = "Role Seeding Done Sucessfully"
            };
        }
    }
}
