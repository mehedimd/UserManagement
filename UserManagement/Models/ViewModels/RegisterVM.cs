using System.ComponentModel.DataAnnotations;

namespace UserManagement.Models.ViewModels
{
    public class RegisterVM
    {
        [Required]
        public string Name { get; set; }
        [Required]
        public string Designation { get; set; }
        [Required]
        public DateTime DateOfBirth { get; set; }
        [EmailAddress]
        public string? Email { get; set; }
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string Role { get; set; }
    }
}
