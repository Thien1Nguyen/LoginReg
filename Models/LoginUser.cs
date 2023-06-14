#pragma warning disable CS8618
// using statements and namespace go here
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
namespace LoginReg.Models;

public class LoginUser
{
    // No other fields!
    [Required]    
    public string LoginEmail { get; set; }    
    [Required]    
    public string LoginPassword { get; set; } 
}