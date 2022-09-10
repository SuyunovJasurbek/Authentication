namespace jwt.Services;

public interface ITokenService
{
  string Create(Dictionary<string, string > claims);
  bool Validate(string token);
}
