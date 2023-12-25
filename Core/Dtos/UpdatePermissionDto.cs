using System.ComponentModel.DataAnnotations;

namespace jwtAuthAspNet7WebApi.Core.Dtos
{
    public class UpdatePermissionDto
    {

        [Required(ErrorMessage = "UserName is Required")]
        public string UserName { get; set; }

    }
}
