using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using jwtAuthAspNet7WebApi.Core.Dtos;
using jwtAuthAspNet7WebApi.Core.Entities;
using jwtAuthAspNet7WebApi.Core.Interfaces;
using jwtAuthAspNet7WebApi.Core.OtherObjects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace jwtAuthAspNet7WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
       
        private readonly IAuthServices _authServices;

        public AuthController(IAuthServices authServices)
        {
            _authServices = authServices;
        }


        //Route For Seeding my roles to DB
        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var seedRole = await _authServices.SeedRolesAsync();
            return Ok(seedRole);
        }


        //Route -> Register
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var registerResult = await _authServices.RegisterAsync(registerDto);
            if (registerResult.IsSuceed)
                return Ok(registerResult);

            return BadRequest(registerResult);
        }


        //Route -> Login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var loginResult = await _authServices.LoginAsync(loginDto);

            if(loginResult.IsSuceed)
                return Ok(loginResult);

            return Unauthorized(loginResult);
        }

        //Route ->  make user -> admin
        [HttpPost]
        [Route("make-admin")]
        public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDto updatePermissionDto) 
        {
            var operationResult = await _authServices.MakeAdminAsync(updatePermissionDto);

            if(operationResult.IsSuceed)
                return Ok(operationResult);

            return BadRequest(operationResult);
        }




        //Route -> make user -> owner
        [HttpPost]
        [Route("make-owner")]
        public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto updatePermissionDto)
        {
            var operationResult = await _authServices.MakeOwnerAsync(updatePermissionDto);

            if (operationResult.IsSuceed)
                return Ok(operationResult);

            return BadRequest(operationResult);
        }
    }
}
