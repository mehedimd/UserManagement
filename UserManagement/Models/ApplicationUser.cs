using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace UserManagement.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required]  // Ensures Name is always provided
        public string Name { get; set; } = null!;

        [Required]
        public string Designation { get; set; } = null!;

        [Required]
        public DateTime DateOfBirth { get; set; }

        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiry { get; set; }
    }
}
