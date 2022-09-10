using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace jwt.Services;

public class TokenService : ITokenService
{
    private readonly IConfiguration configuration;

    public TokenService(IConfiguration configuration )
    {
        this.configuration =configuration;
    }

    public string Create(Dictionary<string, string> claims)
    {
        var jwtClaims = claims.Select(j=>new Claim(j.Key, j.Value));

        var key = configuration["Jwt:Key"] ?? throw new NullReferenceException(" nalibal bubb qoldi  key");
        var issuer=configuration["Jwt:Issuer"] ?? throw new NullReferenceException(" null bub qoldi issuer ");
        var audience =configuration["Jwt:Audience"] ?? throw new NullReferenceException(" null bub qoldi  Auidiense "); 

        
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));        
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);           
        var tokenDescriptor = new JwtSecurityToken(
            issuer,
            audience,
            jwtClaims, 
            expires: DateTime.Now.AddMinutes(12),
            signingCredentials: credentials);        
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        
    }


    public bool Validate(string token)
    {
        var key = configuration["Jwt:Key"] ?? throw new NullReferenceException("Key null bub qoldi .");
        var issuer = configuration["Jwt:Issuer"] ?? throw new NullReferenceException("Issiur null bub qoldi .");
        var secret = Encoding.UTF8.GetBytes(key);           
        var securityKey = new SymmetricSecurityKey(secret);
        var tokenHandler = new JwtSecurityTokenHandler(); 
        try 
        {
            tokenHandler.ValidateToken(
                token, 
                new TokenValidationParameters   
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true, 
                    ValidateAudience = true,    
                    ValidIssuer = issuer,
                    ValidAudience = issuer, 
                    IssuerSigningKey = securityKey,
                }, 
                out SecurityToken validatedToken);            
        }
        catch
        {
            return false;
        }
        return true;    
    }
}