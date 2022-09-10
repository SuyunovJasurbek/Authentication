using jwt.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
namespace jwt.Controllers;

[ApiController]
[Route("/accont")]
public class HomeController :ControllerBase
{
   
 [HttpPost("[action]")]
 public IActionResult Login ([FromServices] ITokenService _tokenService , string username , string password)
 {

   if(username=="jasurbek" && password=="Suyunov" )
   {
    return Ok(_tokenService.Create(
        new Dictionary<string, string>
        {
         {"role", "admin"},
         {"username", "admin"},
         {"email", "admin@gmail.com"},
         {"dob", DateTime.Now.AddYears(-23).ToString()}
        }
    ));
   }

   return Forbid();
 }


    [Authorize(Roles = "superadmin")]
    [HttpGet]
        public IActionResult Secret() => Ok("Secret");
    }

