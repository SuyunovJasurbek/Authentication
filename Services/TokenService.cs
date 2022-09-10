using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace jwt.Services;

public class TokenService : ITokenService
{
    private readonly IConfiguration _configuration;

    public TokenService(IConfiguration configuration )
    {
        _configuration =configuration;
    }


    public string CreateAsync(Dictionary<string, string> claims)
    {
        var jwtClaims = claims.Select(j=>new Claim(j.Key, j.Value));

        var key = _configuration["Jwt:Key"] ?? throw new NullReferenceException(" nalibal bubb qoldi  key");
        var issuer=_configuration["Jwt:Issuer"] ?? throw new NullReferenceException(" null bub qoldi issuer ");
        var auidiense =_configuration["Jwt:Auidiense"] ?? throw new NullReferenceException(" null bub qoldi  Auidiense "); 
         var keyx = _configuration["Jwt:Keyx"] ?? throw new NullReferenceException(" nalibal bubb qoldi  key");

        
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));        
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.Aes128CbcHmacSha256);           
        var tokenDescriptor = new JwtSecurityToken(
            issuer,
            auidiense,
            jwtClaims, 
            expires: DateTime.Now.AddMinutes(1),
            signingCredentials: credentials);        
        return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        
    }



    public bool ValidateAsync(string token)
    {
        var key = _configuration["Jwt:Key"] ?? throw new NullReferenceException("JWT Key is null.");
        var issuer = _configuration["Jwt:Issuer"] ?? throw new NullReferenceException("JWT Issuer is null.");
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