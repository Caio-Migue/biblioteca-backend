using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginModel model)
    {
        // Valide o usuário (exemplo simples)
        if (model.Username == "admin" && model.Password == "senha")
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, model.Username)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("sua_chave_secreta_super_segura"));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: "sua_aplicacao",
                audience: "sua_aplicacao",
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds);

            return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
        }

        return Unauthorized();
    }
}

public class LoginModel
{
    public string Username { get; set; }
    public string Password { get; set; }
}