using System.ComponentModel.DataAnnotations;

namespace UserManagement.Models.ViewModels
{
    public class LoginVM
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
