using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController : BaseApiController
{
    private readonly DataContext _ctx;
    private readonly ITokenService _tokenService;

    public AccountController(DataContext ctx, ITokenService tokenService)

    {
        _ctx = ctx;
        _tokenService = tokenService;
    }

    [HttpPost("register")] // api/account/register
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {
        if (await UserExists(registerDto.Username)) return BadRequest("Username is taken");
        // initialized without a key.
        using var hmac = new HMACSHA512(); // `using` keyword invokes gc
        
        var user = new AppUser()
        {
            UserName = registerDto.Username.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            // Generate the key for validating password in login process. 
            PasswordSalt = hmac.Key
        };

        _ctx.Users.Add(user);
        await _ctx.SaveChangesAsync();
        return new UserDto
        {
            Username = user.UserName,
            Token = _tokenService.CreateToken(user)
        };
    }

    [HttpPost("login")]
    public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
    {
        var user = await _ctx.Users.SingleOrDefaultAsync(x => 
            x.UserName == loginDto.Username);
        if (user == null) return Unauthorized("invalid user name");
        
        // if hmac is initialized with a key 
        // calling ComputeHash on it will always yield a result associated to that key.
        using var hmac = new HMACSHA512(user.PasswordSalt); 
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.password));

        var computedHashLength = computedHash.Length;
        for (int i = 0; i < computedHashLength; i++)
        {
            if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("invalid password");
        }

        return new UserDto
        {
            Username = user.UserName,
            Token = _tokenService.CreateToken(user)
        };

    }
    private async Task<bool> UserExists(string username)
    {
        return await _ctx.Users.AnyAsync(x => x.UserName == username.ToLower());
    }
}