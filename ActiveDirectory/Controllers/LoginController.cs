using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using ActiveDirectory.Helpers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace ActiveDirectory.Controllers {
    [Route("[controller]")]
    [ApiController]
    public class LoginController : ControllerBase {

        [AllowAnonymous]
        [HttpGet]
        public ActionResult<string> Get() {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("alskdjfklasdkalskdjfklasdkalskdjfklasdkalskdjfklasdk"));

            // create some signing credentials using out key
            // encoding our credentials for security using our key generated from our secret
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // create a JWT. Here we chose our Audience which determines the uses of our token.
            // This token has refresh as its only Audience so that it can't be used as an access token
            // Seeing as this token is our refresh token then it is valid for 10000 minutes(subject to change)
            var refreshToken = new JwtSecurityToken(
                issuer: "CQLCORP",
                audience: "Refresh",
    
                expires: DateTime.Now.AddDays(7), // how long you wish the token to be active for
                signingCredentials: creds);

            //Same as above except this is an Access token and can't be used as a refresh token
            //As this is our Access token it is only valid for 15 minutes
            var accessToken = new JwtSecurityToken(
               issuer: "CQLCORP",
               audience: "Access",
 
               expires: DateTime.Now.AddMinutes(15), // how long you wish the token to be active for
               signingCredentials: creds);

            //stringify tokens so they can be returned
            var Refreshtoken = new JwtSecurityTokenHandler().WriteToken(refreshToken);
            var Accesstoken = new JwtSecurityTokenHandler().WriteToken(accessToken);

            ////lambda checks if this is the user's first login
            //var ExistingEmployee = _context.AuthIdserver.ToList().Any(x => x.ActiveDirectoryId == user.Guid);

            ////if employee has logged in before
            //if (ExistingEmployee == false) {
            //    return BadRequest("Employee trying to login does not exist in the database yet...");
            //}
            //else {
            //    //Update their refresh token to the new one just generated and store this in the database
            //    var empAuthId = _context.AuthIdserver
            //        .FirstOrDefault(x => x.ActiveDirectoryId == user.Guid);
            //    empAuthId.RefreshToken = Refreshtoken;
            //    _context.SaveChanges();
            //    //checks if the employee is an admin
            //    isAdmin = _context.AuthIdserver
            //        .ToList()
            //        .Where(x => x.ActiveDirectoryId == user.Guid)
            //        .Select(x => x.IsAdmin)
            //        .FirstOrDefault();
            //}

            // returning the need information about the employee logged in with their tokens
            List<object> returnList = new List<object>();
            var returnInformation = new {
                Refreshtoken,
                Accesstoken,
                accessToken.ValidTo
            };
            returnList.Add(returnInformation);

            return Ok(returnList);
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody] AuthRequest request) {
            // Creating a context that allows us to connect to our Domain Controller
            using (var adContext = new PrincipalContext(ContextType.Domain, "CQLCORP")) {
                // Validating the credentials given with our Active Directory
                // If given credentials are not valid then Unauthorized is returned
                var result = adContext.ValidateCredentials(request.username, request.password);

                //Taking the username and finding the user who might be trying to log in
                var user = UserPrincipal.FindByIdentity(adContext, request.username);
                if (result) {
                    // boolean to store whether the user is an admin
                    bool isAdmin = false;

                    var AccessClaims = new[]
                    {
                        // Get the user's Name
                        new Claim(ClaimTypes.Name, request.username)
                    };

                    // Read our custom key string into a a usable key object 
                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("alskdjfklaslskdjfklaslskdjfklasdk"));

                    // create some signing credentials using out key
                    // encoding our credentials for security using our key generated from our secret
                    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                    // create a JWT. Here we chose our Audience which determines the uses of our token.
                    // This token has refresh as its only Audience so that it can't be used as an access token
                    // Seeing as this token is our refresh token then it is valid for 10000 minutes(subject to change)
                    var refreshToken = new JwtSecurityToken(
                        issuer: "CQLCORP",
                        audience: "Refresh",
                        claims: AccessClaims,
                        expires: DateTime.Now.AddDays(7), // how long you wish the token to be active for
                        signingCredentials: creds);

                    //Same as above except this is an Access token and can't be used as a refresh token
                    //As this is our Access token it is only valid for 15 minutes
                    var accessToken = new JwtSecurityToken(
                       issuer: "CQLCORP",
                       audience: "Access",
                       claims: AccessClaims, // the claims listed above
                       expires: DateTime.Now.AddMinutes(15), // how long you wish the token to be active for
                       signingCredentials: creds);

                    //stringify tokens so they can be returned
                    var Refreshtoken = new JwtSecurityTokenHandler().WriteToken(refreshToken);
                    var Accesstoken = new JwtSecurityTokenHandler().WriteToken(accessToken);

                    ////lambda checks if this is the user's first login
                    //var ExistingEmployee = _context.AuthIdserver.ToList().Any(x => x.ActiveDirectoryId == user.Guid);

                    ////if employee has logged in before
                    //if (ExistingEmployee == false) {
                    //    return BadRequest("Employee trying to login does not exist in the database yet...");
                    //}
                    //else {
                    //    //Update their refresh token to the new one just generated and store this in the database
                    //    var empAuthId = _context.AuthIdserver
                    //        .FirstOrDefault(x => x.ActiveDirectoryId == user.Guid);
                    //    empAuthId.RefreshToken = Refreshtoken;
                    //    _context.SaveChanges();
                    //    //checks if the employee is an admin
                    //    isAdmin = _context.AuthIdserver
                    //        .ToList()
                    //        .Where(x => x.ActiveDirectoryId == user.Guid)
                    //        .Select(x => x.IsAdmin)
                    //        .FirstOrDefault();
                    //}

                    // returning the need information about the employee logged in with their tokens
                    List<object> returnList = new List<object>();
                    var returnInformation = new {
                        Refreshtoken,
                        Accesstoken,
                        accessToken.ValidTo,
                        user.GivenName,
                        isAdmin
                    };
                    returnList.Add(returnInformation);

                    return Ok(returnList);
                }

            }

            // if we haven't returned by now, something went wrong and the user is not authorized
            return Unauthorized();
        }
    }
}
