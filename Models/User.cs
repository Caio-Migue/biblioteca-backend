using System.ComponentModel.DataAnnotations;

public class User
{
    [Key] // Indica que esta propriedade é a chave primária
    public int Id { get; set; }

    [Required(ErrorMessage = "O nome é obrigatório.")]
    [StringLength(100, ErrorMessage = "O nome não pode exceder 100 caracteres.")]
    public string Name { get; set; }

    [Required(ErrorMessage = "O CPF é obrigatório.")]
    [RegularExpression(@"^\d{11}$", ErrorMessage = "O CPF deve ter 11 dígitos.")]
    public string CPF { get; set; } // Validação do CPF para ter exatamente 11 dígitos

    [StringLength(50, ErrorMessage = "O número de matrícula não pode exceder 50 caracteres.")]
    public string? RegistrationNumber { get; set; }

    [Required(ErrorMessage = "O endereço é obrigatório.")]
    public string Address { get; set; }

    [Phone(ErrorMessage = "Formato de telefone inválido.")]
    public string? Phone { get; set; }

    [Required(ErrorMessage = "O status de ativo é obrigatório.")]
    public bool IsActive { get; set; }

    [Required(ErrorMessage = "O papel é obrigatório.")]
    public EUserRole Role { get; set; } // Atributo para definir o papel do usuário

    public string Username { get; set; }
    public string Password { get; set; }
    // Adicione outros campos conforme necessário (ex: Role, Email)

    public User()
    {

    }
    public User(string name, string cpf, string address, bool isActive, EUserRole role, string? registrationNumber = null, string? phone = null)
    {
        Name = name;
        CPF = cpf;
        Address = address;
        IsActive = isActive;
        Role = role;
        RegistrationNumber = registrationNumber;
        Phone = phone;
    }
}
