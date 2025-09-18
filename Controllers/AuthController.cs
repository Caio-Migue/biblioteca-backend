using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly LibraryContext _context;

    public AuthController(LibraryContext context)
    {
        _context = context;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel model)
    {
        // Busca o usuário no banco
        var usuario = await _context.Users
            .FirstOrDefaultAsync(u => u.Username == model.Username && u.Password == model.Password);

        if (usuario != null)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, usuario.Username),
                // Adicione outros claims conforme necessário
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("@biblioteca2025"));
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

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterModel model)
    {
        // Verifica se já existe usuário com o mesmo username
        if (await _context.Users.AnyAsync(u => u.Username == model.Username))
            return BadRequest("Usuário já existe.");

        var user = new User
        {
            Username = model.Username,
            Password = model.Password, // Ideal: salvar hash da senha!
            Name = model.Name,
            CPF = model.CPF,
            Address = model.Address,
            IsActive = true,
            Role = model.Role,
            RegistrationNumber = model.RegistrationNumber,
            Phone = model.Phone
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return Ok("Usuário registrado com sucesso.");
    }
}

public class LoginModel
{
    public string Username { get; set; }
    public string Password { get; set; }
}

public class RegisterModel
{
    public string Username { get; set; }
    public string Password { get; set; }
    public string Name { get; set; }
    public string CPF { get; set; }
    public string Address { get; set; }
    public EUserRole Role { get; set; }
    public string? RegistrationNumber { get; set; }
    public string? Phone { get; set; }
}