using MinimalJwt.Models;
using MinimalJwt.Repositories;

namespace MinimalJwt.Services;

public sealed class UserService : IUserService
{
    public User Get(UserLogin userLogin)
    {
        var user = UserRepository.Users.FirstOrDefault(user =>
            user.Username.Equals(userLogin.UserName, StringComparison.OrdinalIgnoreCase) &&
            user.Password.Equals(userLogin.Password));
        return user;
    }
}