using System.ComponentModel.DataAnnotations;

namespace jwtAuthAspNet7WebApi.Core.Dtos
{
    public class RegisterDto
    {
        [Required(ErrorMessage = "FirstName is Required")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "LastName is Required")]
        public string LastName { get; set; }

        [Required(ErrorMessage ="UserName is Required")]
        public string UserName {get;  set;}

        [Required(ErrorMessage = "Email is Required")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is Required")]
        public string Password { get; set; }
    }
}
