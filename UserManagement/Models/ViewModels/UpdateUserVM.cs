using System.ComponentModel.DataAnnotations;

namespace UserManagement.Models.ViewModels
{
    public class UpdateUserVM
    {
        [Required]
        public string Name { get; set; }
        public string? Email { get; set; }
        [Required]
        public string Designation { get; set; }
    }
}
