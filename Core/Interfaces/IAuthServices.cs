using jwtAuthAspNet7WebApi.Core.Dtos;

namespace jwtAuthAspNet7WebApi.Core.Interfaces
{
    public interface IAuthServices
    {
        Task<AuthServicesResponseDto> SeedRolesAsync();

        Task<AuthServicesResponseDto> RegisterAsync(RegisterDto registerDto);

        Task<AuthServicesResponseDto> LoginAsync(LoginDto loginDto);

        Task<AuthServicesResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto);

        Task<AuthServicesResponseDto> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto);
    }
}
