namespace jwt.Services;

public interface ITokenService
{
  String CreateAsync(Dictionary<string, string > claims);
  bool ValidateAsync(string token);
}