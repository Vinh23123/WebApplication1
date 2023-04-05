using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Text.RegularExpressions;
using WebApplication1.Context;
using WebApplication1.Helpers;
using WebApplication1.Models;

using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using WebApplication1.Models.Dto;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }


        [HttpPost("Authenticate")]

        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            var user = await _authContext.Users.
                FirstOrDefaultAsync(x => x.Username == userObj.Username);

            if(user == null)
                return NotFound(new {Message = "User Not Found"});

            if(PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new {Message="Password is Incorret"});
            }
            user.Token = CreateJwt(user);
            var newAccessToken = user.Token; // method create a new access token
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpireTime = DateTime.Now.AddDays(5);
            await _authContext.SaveChangesAsync();

            return Ok(new TokenApiDto()
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken
            });
        }



        [HttpPost("register")]

        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();
              
            //check username
            if(await CheckUserNameExistAsync(userObj.Username))
                return BadRequest(new {Message = "Username Already Exist" });

            //Check email

            if (await CheckEmailExistAsync(userObj.Email))
                return BadRequest(new { Message = "Email Already Exist"});



            //check password streght
            var pass = CheckPasswordStrenght(userObj.Password);
            if(!string.IsNullOrEmpty(pass))
                return BadRequest(new {Message =pass.ToString() });

            
            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
           await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "User Registered" });
        }
        private Task<bool> CheckUserNameExistAsync(string username)
        //{
            //return await _authContext.Users.AnyAsync(x => x.Username == username);
        //}

        => _authContext.Users.AnyAsync(x => x.Username == username);


        private Task<bool> CheckEmailExistAsync(string email)
         //{
        //return await _authContext.Users.AnyAsync(x => x.Username == username);
        //}

        => _authContext.Users.AnyAsync(x => x.Email == email);


        private string CheckPasswordStrenght(string password)
        {
            StringBuilder sb = new StringBuilder();
            if(password.Length < 8)
              sb.Append("Minimum password legth should be 8"+Environment.NewLine);

            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]")
                && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be Alphanumeric" + Environment.NewLine);
            if (!Regex.IsMatch(password, "[<,>,@,!,#,$,%,^,&,*,(,),_,+,\\[,\\],{,},?,:,;,|,~,`,-,=]"))
                sb.Append("Password should contain special chars" + Environment.NewLine);
            return sb.ToString();
        }



        // Create jwt (token)
          private string CreateJwt(User user)
        {
            var JwtTokenHandler = new JwtSecurityTokenHandler();
            var key  = Encoding.ASCII.GetBytes("veryveryverysceret.....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new  Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.Username}"),
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(10), // certain time
                SigningCredentials = credentials
            };
            var token = JwtTokenHandler.CreateToken(tokenDescriptor);   
                    return JwtTokenHandler.WriteToken(token);
        }


        private string CreateRefreshToken()
        {
            var tokenBytes = RandomNumberGenerator.GetBytes(64);
            var refreshToken = Convert.ToBase64String(tokenBytes);

            var tokenInUser = _authContext.Users
                .Any(a=>a.RefreshToken== refreshToken);
            if(tokenInUser)
            {
                return CreateRefreshToken();
            }
            return refreshToken;
        }

        //method get priciple value like payload vulue from the token
        private ClaimsPrincipal GetPrincipleFromExpiredToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryveryverysceret.....");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false,
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var pricipal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("This is InValid Token");
            return pricipal;
        }

        [Authorize]
        [HttpGet]
        public async Task<ActionResult <User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }

        // give new access token
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
        {
            if (tokenApiDto is null)
                return BadRequest("Invalid Client Request");
            string accessToken = tokenApiDto.AccessToken;
            string refreshToken = tokenApiDto.RefreshToken;
            var priciple = GetPrincipleFromExpiredToken(accessToken);
            var username = priciple.Identity.Name;
            var user = await _authContext.Users.FirstOrDefaultAsync(u => u.Username == username);
            if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpireTime <= DateTime.Now)
                return BadRequest("Invalid Request");
            var newAccessToken = CreateJwt(user);
            var newRefreshToken = CreateRefreshToken();
            user.RefreshToken = newRefreshToken;
            await _authContext.SaveChangesAsync();
            return Ok(new TokenApiDto { AccessToken = accessToken, RefreshToken = refreshToken, });
        }
    }
}
