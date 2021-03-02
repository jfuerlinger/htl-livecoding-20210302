using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using MyAuth.Core.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Utils;
using System.Linq;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using MyAuth.Api_Jwt.DataTransferObjects;

namespace MyAuth.Api_Jwt.Controllers
{
  [ApiController]
  [Route("[controller]")]
  public class AuthController : ControllerBase
  {
    private static List<AuthUser> _users = new List<AuthUser>
    {
      new AuthUser { Email = "admin@htl.at", Password=AuthUtils.GenerateHashedPassword("admin"), UserRole = "Admin" },
      new AuthUser { Email = "user@htl.at", Password=AuthUtils.GenerateHashedPassword("user"), UserRole = "User" }
    };

    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _config;

    public AuthController(ILogger<AuthController> logger,
      IConfiguration config )
    {
      _logger = logger;
      _config = config;
    }

    [Route("login")]
    [HttpPost]
    public IActionResult Login(AuthUserDto userDto)
    {
      var authUser = _users.SingleOrDefault(u => u.Email == userDto.Email);
      if(authUser == null)
      {
        return Unauthorized();
      }

      if(!AuthUtils.VerifyPassword(userDto.Password, authUser.Password))
      {
        return Unauthorized();
      }

      var tokenString = GenerateJwtToken(authUser);

      IActionResult response = Ok(new
      {
        auth_token = tokenString,
        userMail = authUser.Email,
      });

      return response;
    }


    /// <summary>
    /// JWT erzeugen. Minimale Claim-Infos: Email und Rolle
    /// </summary>
    /// <param name="userInfo"></param>
    /// <returns>Token mit Claims</returns>
    private string GenerateJwtToken(AuthUser userInfo)
    {
      var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]));
      var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

      var authClaims = new List<Claim>();
      authClaims.Add(new Claim(ClaimTypes.Email, userInfo.Email));
      authClaims.Add(new Claim(ClaimTypes.Country, "Austria"));
      if (!string.IsNullOrEmpty(userInfo.UserRole))
      {
        authClaims.Add(new Claim(ClaimTypes.Role, userInfo.UserRole));
      }

      var token = new JwtSecurityToken(
        issuer: _config["Jwt:Issuer"],
        audience: _config["Jwt:Audience"],
        claims: authClaims,
        expires: DateTime.Now.AddMinutes(30),
        signingCredentials: credentials);

      return new JwtSecurityTokenHandler().WriteToken(token);
    }
  }
}
