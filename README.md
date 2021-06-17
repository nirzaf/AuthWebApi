# aspnet-core-3-jwt-refresh-tokens-api

ASP.NET Core 3.1 API - JWT Authentication with Refresh Tokens


ASP.NET Core 3.1

Other versions available:

.NET: .NET 5.0
Node: Node.js + MongoDB
In this tutorial we'll go through an example of how to implement JWT (JSON Web Token) authentication with refresh tokens in an ASP.NET Core 3.1 API.

For an extended example that includes email sign up, verification, forgot password and user management (CRUD) functionality see ASP.NET Core 3.1 - Boilerplate API with Email Sign Up, Verification, Authentication & Forgot Password.

The example API has the following endpoints/routes to demonstrate authenticating with JWT, refreshing and revoking tokens, and accessing secure routes:

/users/authenticate - public route that accepts HTTP POST requests containing a username and password in the body. If the username and password are correct then a JWT authentication token and the user details are returned in the response body, and a refresh token cookie (HTTP Only) is returned in the response headers.
/users/refresh-token - public route that accepts HTTP POST requests with a refresh token cookie. If the cookie exists and the refresh token is valid then a new JWT authentication token and the user details are returned in the response body, a new refresh token cookie (HTTP Only) is returned in the response headers and the old refresh token is revoked.
/users/revoke-token - secure route that accepts HTTP POST requests containing a refresh token either in the body or in a cookie, if both are present the token in the body is used. If the refresh token is valid and active then it is revoked and can no longer be used to refresh JWT tokens.
/users - secure route that accepts HTTP GET requests and returns a list of all the users in the application if the HTTP Authorization header contains a valid JWT token. If there is no auth token or the token is invalid then a 401 Unauthorized response is returned.
/users/{id} - secure route that accepts HTTP GET requests and returns the details of the user with the specified id.
/users/{id}/refresh-tokens - secure route that accepts HTTP GET requests and returns a list of all refresh tokens (active and revoked) of the user with the specified id.
To keep the api code as simple as possible, it is configured to use the EF Core InMemory database provider which allows Entity Framework Core to create and connect to an in-memory database rather than you having to install a real db server. This can be easily switched out to a real db provider when you're ready to work with a database such as SQL Server, Oracle, MySql etc. For an example api that uses SQLite in development and SQL Server in production see this post.

The tutorial project is available on GitHub at https://github.com/cornflourblue/aspnet-core-3-jwt-refresh-tokens-api.


Tutorial Contents
Tools required to develop ASP.NET Core 3.1 applications
Running the example API locally
Testing the API with Postman
Running an Angular 9 app with the ASP.NET Core API
ASP.NET Core API project structure

Tools required to run the ASP.NET Core 3.1 JWT Example Locally
To develop and run ASP.NET Core applications locally, download and install the following:

.NET Core SDK - includes the .NET Core runtime and command line tools
Visual Studio Code - code editor that runs on Windows, Mac and Linux
C# extension for Visual Studio Code - adds support to VS Code for developing .NET Core applications
For detailed instructions see ASP.NET Core - Setup Development Environment.


Running the ASP.NET Core JWT with Refresh Tokens API Locally
Download or clone the tutorial project code from https://github.com/cornflourblue/aspnet-core-3-jwt-refresh-tokens-api
Start the api by running dotnet run from the command line in the project root folder (where the WebApi.csproj file is located), you should see the message Now listening on: http://localhost:4000. Follow the instructions below to test with Postman or hook up with the example Angular application available.
Starting in debug mode
You can also start the application in debug mode in VS Code by opening the project root folder in VS Code and pressing F5 or by selecting Debug -> Start Debugging from the top menu. Running in debug mode allows you to attach breakpoints to pause execution and step through the application code.

Before running in production
Before running in production make sure that you update the Secret property in the appsettings.json file, it is used to sign and verify JWT tokens for authentication, change it to a random string to ensure nobody else can generate a JWT with the same secret and gain unauthorized access to your api. A quick and easy way is join a couple of GUIDs together to make a long random string (e.g. from https://www.guidgenerator.com/).




Testing the API with Postman
Postman is a great tool for testing APIs, you can download it at https://www.getpostman.com/.

Below are instructions on how to use Postman to authenticate a user to get a JWT token and refresh token from the api, refresh and revoke tokens, and retrieve user details from secure routes using JWT.

How to authenticate a user with Postman
To authenticate a user to get a JWT token and refresh token follow these steps:

Open a new request tab by clicking the plus (+) button at the end of the tabs.
Change the http request method to "POST" with the dropdown selector on the left of the URL input field.
In the URL field enter the address to the authenticate route of your local API - http://localhost:4000/users/authenticate.
Select the "Body" tab below the URL field, change the body type radio button to "raw", and change the format dropdown selector to "JSON".
Enter a JSON object containing the test username and password in the "Body" textarea:
{
    "username": "test",
    "password": "test"
}
Click the "Send" button, you should receive a "200 OK" response with the user details including a JWT token in the response body and a refresh token in the response cookies.
Here's a screenshot of Postman after the request is sent and the user has been authenticated:


And this is the response cookies tab with the refresh token:



How to refresh a token with Postman
This step can only be done after the above authenticate step because a valid refresh token cookie is required.

To use a refresh token cookie to get a new JWT token and a new refresh token follow these steps:

Open a new request tab by clicking the plus (+) button at the end of the tabs.
Change the http request method to "POST" with the dropdown selector on the left of the URL input field.
In the URL field enter the address to the refresh token route of your local API - http://localhost:4000/users/refresh-token.
Click the "Send" button, you should receive a "200 OK" response with the user details including a JWT token in the response body and a refresh token in the response cookies. Make a copy of the JWT token value because we'll be using it in the next steps to make authenticated requests.
Here's a screenshot of Postman after the request is sent and the token has been refreshed:


And this is the response cookies tab with the new refresh token:



How to make an authenticated request to retrieve all users
To make an authenticated request to get all users with the JWT token from the previous step, follow these steps:

Open a new request tab by clicking the plus (+) button at the end of the tabs.
Change the http request method to "GET" with the dropdown selector on the left of the URL input field.
In the URL field enter the address to the users route of your local API - http://localhost:4000/users.
Select the "Authorization" tab below the URL field, change the type to "Bearer Token" in the type dropdown selector, and paste the JWT token from the previous step into the "Token" field.
Click the "Send" button, you should receive a "200 OK" response containing a JSON array with all the user records in the system (just the one test user in the example).
Here's a screenshot of Postman after making an authenticated request to get all users:



How to retrieve all of a user's refresh tokens
To get all refresh tokens for a user including active and revoked tokens, follow these steps:

Open a new request tab by clicking the plus (+) button at the end of the tabs.
Change the http request method to "GET" with the dropdown selector on the left of the URL input field.
In the URL field enter the address to the users route of your local API - http://localhost:4000/users/1/refresh-tokens.
Select the "Authorization" tab below the URL field, change the type to "Bearer Token" in the type dropdown selector, and paste the JWT token from the previous authenticate (or refresh token) step into the "Token" field.
Click the "Send" button, you should receive a "200 OK" response containing a JSON array with all the test user's refresh tokens. Make a copy of the last token value (the active token) because we'll use it in the next step to revoke the token.
Here's a screenshot of Postman after making an authenticated request to get all refresh tokens for the test user:



How to revoke a token with Postman
To revoke a refresh token so it can no longer be used to generate JWT tokens, follow these steps:

Open a new request tab by clicking the plus (+) button at the end of the tabs.
Change the http request method to "POST" with the dropdown selector on the left of the URL input field.
In the URL field enter the address to the authenticate route of your local API - http://localhost:4000/users/revoke-token.
Select the "Authorization" tab below the URL field, change the type to "Bearer Token" in the type dropdown selector, and paste the JWT token from the previous authenticate (or refresh token) step into the "Token" field.
Select the "Body" tab below the URL field, change the body type radio button to "raw", and change the format dropdown selector to "JSON".
Enter a JSON object containing the active refresh token from the previous step in the "Body" textarea, e.g:
{
    "token": "ENTER THE ACTIVE REFRESH TOKEN HERE"
}
Click the "Send" button, you should receive a "200 OK" response with the message Token revoked.
NOTE: You can also revoke the token in the refreshToken cookie with the /users/revoke-token route, to revoke the refresh token cookie simply send the same request with an empty body.

Here's a screenshot of Postman after making the request and the token has been revoked:


 


Running an Angular app with the JWT Refresh Tokens API
For full details about the example Angular  application see the post Angular 9 - JWT Authentication with Refresh Tokens. But to get up and running quickly just follow the below steps.

Download or clone the Angular 9 tutorial code from https://github.com/cornflourblue/angular-9-jwt-refresh-tokens
Install all required npm packages by running npm install from the command line in the project root folder (where the package.json is located).
Remove or comment out the line below the comment // provider used to create fake backend located in the /src/app/app.module.ts file.
Start the application by running npm start from the command line in the project root folder, this will launch a browser displaying the Angular example application and it should be hooked up with the ASP.NET Core JWT Refresh Tokens API that you already have running.
 
ASP.NET Core API Project Structure
The tutorial project is organised into the following folders:
Controllers - define the end points / routes for the web api, controllers are the entry point into the web api from client applications via http requests.
Models - represent request and response models for controller methods, request models define the parameters for incoming requests, and response models can be used to define what data is returned.
Services - contain core business logic, validation and data access code.
Entities - represent the application data stored in the database.
Helpers - anything that doesn't fit into the above folders.

Click any of the below links to jump down to a description of each file along with its code:

Controllers
UsersController.cs
Entities
RefreshToken.cs
User.cs
Helpers
AppSettings.cs
DataContext.cs
Models
AuthenticateRequest.cs
AuthenticateResponse.cs
RevokeTokenRequest.cs
Services
UserService.cs
appsettings.Development.json
appsettings.json
Program.cs
Startup.cs
WebApi.csproj
 
Users Controller
Path: /Controllers/UsersController.cs
The ASP.NET Core users controller defines and handles all routes / endpoints for the api that relate to users, this includes authentication, refreshing and revoking tokens, and retrieving user and refresh token data. Within each route the controller calls the user service to perform the action required, this enables the controller to stay 'lean' and completely separate from the business logic and data access code.

The controller actions are secured with JWT using the [Authorize] attribute, with the exception of the Authenticate and RefreshToken methods which allow public access by overriding the [Authorize] attribute on the controller with an [AllowAnonymous] attribute on each action method. I chose this approach so any new action methods added to the controller will be secure by default unless explicitly made public.

The setTokenCookie() helper method appends an HTTP Only cookie with the refresh token to the response for increased security. HTTP Only cookies are not accessible to client-side javascript which prevents XSS (cross site scripting), and the refresh token can only be used to fetch a new token from the /users/refresh-token route which prevents CSRF (cross site request forgery).

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using WebApi.Services;
using WebApi.Models;
using Microsoft.AspNetCore.Http;
using System;

namespace WebApi.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        [AllowAnonymous]
        [HttpPost("authenticate")]
        public IActionResult Authenticate([FromBody] AuthenticateRequest model)
        {
            var response = _userService.Authenticate(model, ipAddress());

            if (response == null)
                return BadRequest(new { message = "Username or password is incorrect" });

            setTokenCookie(response.RefreshToken);

            return Ok(response);
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public IActionResult RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var response = _userService.RefreshToken(refreshToken, ipAddress());

            if (response == null)
                return Unauthorized(new { message = "Invalid token" });

            setTokenCookie(response.RefreshToken);

            return Ok(response);
        }

        [HttpPost("revoke-token")]
        public IActionResult RevokeToken([FromBody] RevokeTokenRequest model)
        {
            // accept token from request body or cookie
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            var response = _userService.RevokeToken(token, ipAddress());

            if (!response)
                return NotFound(new { message = "Token not found" });

            return Ok(new { message = "Token revoked" });
        }

        [HttpGet]
        public IActionResult GetAll()
        {
            var users = _userService.GetAll();
            return Ok(users);
        }

        [HttpGet("{id}")]
        public IActionResult GetById(int id)
        {
            var user = _userService.GetById(id);
            if (user == null) return NotFound();

            return Ok(user);
        }

        [HttpGet("{id}/refresh-tokens")]
        public IActionResult GetRefreshTokens(int id)
        {
            var user = _userService.GetById(id);
            if (user == null) return NotFound();

            return Ok(user.RefreshTokens);
        }

        // helper methods

        private void setTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
    }
}
Back to top
 
Refresh Token Entity
Path: /Entities/RefreshToken.cs
The refresh token entity class represents the data for a refresh token in the application.

Entity classes define the tables and properties stored in the database, they are also used to pass data between different parts of the application (e.g. between services and controllers) and can be used to return http response data from controller action methods. If a controller action method requires custom data to be returned (e.g. multiple different entity types) then a custom response model class can be created in the Models folder.

The [Owned] attribute marks the refresh token class as an owned entity type, meaning it can only exist as a child / dependant of another entity class. In this example a refresh token is always owned by a user entity.

The [Key] attribute explicitly sets the id field as the primary key in the database table. Properties with the name Id are automatically made primary keys by EF Core, however in the case of Owned entities EF Core creates a composite primary key consisting of the id and the owner id which can cause errors with auto generated id fields. Explicitly marking the id with the [Key] attribute tells EF Core to make only the id field the primary key in the db table.

The [JsonIgnore] attribute prevents the id from being serialized and returned with refresh token data in api responses.

using System;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;

namespace WebApi.Entities
{
    [Owned]
    public class RefreshToken
    {
        [Key]
        [JsonIgnore]
        public int Id { get; set; }
        
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public bool IsExpired => DateTime.UtcNow >= Expires;
        public DateTime Created { get; set; }
        public string CreatedByIp { get; set; }
        public DateTime? Revoked { get; set; }
        public string RevokedByIp { get; set; }
        public string ReplacedByToken { get; set; }
        public bool IsActive => Revoked == null && !IsExpired;
    }
}
Back to top
 
User Entity
Path: /Entities/User.cs
The user entity class represents the data for a user in the application.

Entity classes define the tables and properties stored in the database, they are also used to pass data between different parts of the application (e.g. between services and controllers) and can be used to return http response data from controller action methods. If a controller action method requires custom data to be returned (e.g. multiple different entity types) then a custom response model class can be created in the Models folder.

The [JsonIgnore] attribute prevents the password and refresh tokens properties from being serialized and returned with user data in api responses. There is a dedicated route for fetching refresh token data (/users/{id}/refresh-tokens).

using System.Text.Json.Serialization;
using System.Collections.Generic;

namespace WebApi.Entities
{
    public class User
    {
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Username { get; set; }

        [JsonIgnore]
        public string Password { get; set; }

        [JsonIgnore]
        public List<RefreshToken> RefreshTokens { get; set; }
    }
}
Back to top
 
App Settings Class
Path: /Helpers/AppSettings.cs
The app settings class contains properties defined in the appsettings.json file and is used for accessing application settings via objects that are injected into classes using the ASP.NET Core built in dependency injection (DI) system. For example the User Service accesses app settings via an IOptions<AppSettings> appSettings object that is injected into the constructor.

Mapping of configuration sections to classes is done in the ConfigureServices method of the Startup.cs file.

namespace WebApi.Helpers
{
    public class AppSettings
    {
        public string Secret { get; set; }
    }
}
Back to top
 
Data Context
Path: /Helpers/DataContext.cs
The data context class is used for accessing application data through Entity Framework Core. It derives from the EF Core DbContext class and has a public Users property for accessing and managing user data. The data context is used by services such as the user service for handling all low level data (CRUD) operations.

using Microsoft.EntityFrameworkCore;
using WebApi.Entities;

namespace WebApi.Helpers
{
    public class DataContext : DbContext
    {
        public DbSet<User> Users { get; set; }

        public DataContext(DbContextOptions<DataContext> options) : base(options) { }
    }
}
Back to top
 
Authenticate Request Model
Path: /Models/AuthenticateRequest.cs
The authenticate request model defines the parameters for incoming requests to the /users/authenticate route, it is attached to the route as the parameter to the Authenticate action method of the users controller. When an HTTP POST request is received by the route, the data from the body is bound to an instance of the AuthenticateRequest class, validated and passed to the method.

ASP.NET Core Data Annotations are used to automatically handle model validation, the [Required] attribute sets both the username and password as required fields so if either are missing a validation error message is returned from the api.

using System.ComponentModel.DataAnnotations;

namespace WebApi.Models
{
    public class AuthenticateRequest
    {
        [Required]
        public string Username { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
Back to top
 
Authenticate Response Model
Path: /Models/AuthenticateResponse.cs
The authenticate response model defines the data returned after successful authentication. It includes basic user details, a JWT token and a refresh token.

The refresh token has the [JsonIgnore] attribute so it isn't returned in the api response body because it is returned in an HTTP Only cookie for increased security. HTTP Only cookies are not accessible to client-side javascript which prevents XSS (cross site scripting), and the refresh token can only be used to fetch a new token from the /users/refresh-token route which prevents CSRF (cross site request forgery).

using System.Text.Json.Serialization;
using WebApi.Entities;

namespace WebApi.Models
{
    public class AuthenticateResponse
    {
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Username { get; set; }
        public string JwtToken { get; set; }

        [JsonIgnore] // refresh token is returned in http only cookie
        public string RefreshToken { get; set; }

        public AuthenticateResponse(User user, string jwtToken, string refreshToken)
        {
            Id = user.Id;
            FirstName = user.FirstName;
            LastName = user.LastName;
            Username = user.Username;
            JwtToken = jwtToken;
            RefreshToken = refreshToken;
        }
    }
}
Back to top
 
Revoke Token Request Model
Path: /Models/RevokeTokenRequest.cs
The revoke token request model defines the parameters for incoming requests to the /users/revoke-token route of the api, it is attached to the route as the parameter to the RevokeToken action method of the users controller. When an HTTP POST request is received by the route, the data from the body is bound to an instance of the RevokeTokenRequest class, validated and passed to the method.

The Token property is optional in the request body because the route also supports revoking the token sent in the refreshToken cookie. If both are present then the token in the request body is used.

namespace WebApi.Models
{
    public class RevokeTokenRequest
    {
        public string Token { get; set; }
    }
}
Back to top
 
User Service
Path: /Services/UserService.cs
The user service contains the core logic for authentication, generating JWT and refresh tokens, refreshing and revoking tokens, and fetching user data.

The top of the UserService.cs file contains the IUserService interface which defines the public methods for the user service, below the interface is the concrete UserService class that implements the interface.

The Authenticate() method finds a user by username and password to verify credentials and returns the user details with a JWT token and a refresh token. For simplicity passwords are stored as plain text in the example but in production passwords should be hashed, for an example of how to save and verify hashed passwords see the user service in this post.

The RefreshToken() method accepts an active refresh token and returns the user details with a JWT token and a new refresh token. The old refresh token is revoked and can no longer be used, this technique is called "refresh token rotation" and is used to increase application security by making refresh tokens short lived. When a refresh token is rotated the new token is saved in the ReplacedByToken field of the revoked token to create an audit trail.

The RevokeToken() method accepts an active refresh token and revokes it so it can no longer be used. A token is revoked when it has a Revoked date. The ip address of the user that revoked the token is saved in the RevokedByIp field.

The GetAll() method returns a list of all users in the system, and the GetById() method returns the user with the specified id.

The generateJwtToken() helper method returns a short lived JWT token that expires after 15 minutes. The token is created with the JwtSecurityTokenHandler class and digitally signed using the secret key stored in the app settings file.

The generateRefreshToken() helper method returns a new refresh token that expires after 7 days. The created date and user ip address are saved against the token to help in identifying any unusual activity.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using WebApi.Models;
using WebApi.Entities;
using WebApi.Helpers;

namespace WebApi.Services
{
    public interface IUserService
    {
        AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
        AuthenticateResponse RefreshToken(string token, string ipAddress);
        bool RevokeToken(string token, string ipAddress);
        IEnumerable<User> GetAll();
        User GetById(int id);
    }

    public class UserService : IUserService
    {
        private DataContext _context;
        private readonly AppSettings _appSettings;

        public UserService(
            DataContext context,
            IOptions<AppSettings> appSettings)
        {
            _context = context;
            _appSettings = appSettings.Value;
        }

        public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
        {
            var user =  _context.Users.SingleOrDefault(x => x.Username == model.Username && x.Password == model.Password);

            // return null if user not found
            if (user == null) return null;

            // authentication successful so generate jwt and refresh tokens
            var jwtToken = generateJwtToken(user);
            var refreshToken = generateRefreshToken(ipAddress);

            // save refresh token
            user.RefreshTokens.Add(refreshToken);
            _context.Update(user);
            _context.SaveChanges();

            return new AuthenticateResponse(user, jwtToken, refreshToken.Token);
        }

        public AuthenticateResponse RefreshToken(string token, string ipAddress)
        {
            var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            
            // return null if no user found with token
            if (user == null) return null;

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            // return null if token is no longer active
            if (!refreshToken.IsActive) return null;

            // replace old refresh token with a new one and save
            var newRefreshToken = generateRefreshToken(ipAddress);
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            refreshToken.ReplacedByToken = newRefreshToken.Token;
            user.RefreshTokens.Add(newRefreshToken);
            _context.Update(user);
            _context.SaveChanges();

            // generate new jwt
            var jwtToken = generateJwtToken(user);

            return new AuthenticateResponse(user, jwtToken, newRefreshToken.Token);
        }

        public bool RevokeToken(string token, string ipAddress)
        {
            var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));
            
            // return false if no user found with token
            if (user == null) return false;

            var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

            // return false if token is not active
            if (!refreshToken.IsActive) return false;

            // revoke token and save
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = ipAddress;
            _context.Update(user);
            _context.SaveChanges();

            return true;
        }

        public IEnumerable<User> GetAll()
        {
            return _context.Users;
        }

        public User GetById(int id)
        {
            return _context.Users.Find(id);
        }

        // helper methods

        private string generateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[] 
                {
                    new Claim(ClaimTypes.Name, user.Id.ToString())
                }),
                Expires = DateTime.UtcNow.AddMinutes(15),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private RefreshToken generateRefreshToken(string ipAddress)
        {
            using(var rngCryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[64];
                rngCryptoServiceProvider.GetBytes(randomBytes);
                return new RefreshToken
                {
                    Token = Convert.ToBase64String(randomBytes),
                    Expires = DateTime.UtcNow.AddDays(7),
                    Created = DateTime.UtcNow,
                    CreatedByIp = ipAddress
                };
            }
        }
    }
}
Back to top
 
App Settings (Development)
Path: /appsettings.Development.json
Configuration file with application settings that are specific to the development environment.

{
    "Logging": {
        "LogLevel": {
            "Default": "Debug",
            "System": "Information",
            "Microsoft": "Information"
        }
    }
}
Back to top
 
App Settings
Path: /appsettings.json
Root configuration file containing application settings for all environments.

IMPORTANT: The "Secret" property is used to sign and verify JWT tokens for authentication, change it to a random string to ensure nobody else can generate a JWT with the same secret and gain unauthorized access to your api. A quick and easy way is join a couple of GUIDs together to make a long random string (e.g. from https://www.guidgenerator.com/).

{
    "AppSettings": {
        "Secret": "THIS IS USED TO SIGN AND VERIFY JWT TOKENS, REPLACE IT WITH YOUR OWN SECRET, IT CAN BE ANY STRING"
    },
    "Logging": {
        "LogLevel": {
            "Default": "Information",
            "Microsoft": "Warning",
            "Microsoft.Hosting.Lifetime": "Information"
        }
    },
    "AllowedHosts": "*"
}
Back to top
 
ASP.NET Core Program.cs
Path: /Program.cs
The program class is a console app that is the main entry point to start the application, it configures and launches the web api host and web server using an instance of IHostBuilder. ASP.NET Core applications require a host in which to execute.

Kestrel is the web server used in the example, it's a new cross-platform web server for ASP.NET Core that's included in new project templates by default. Kestrel is fine to use on it's own for internal applications and development, but for public facing websites and applications it should sit behind a more mature reverse proxy server (IIS, Apache, Nginx etc) that will receive HTTP requests from the internet and forward them to Kestrel after initial handling and security checks.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace WebApi
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>()
                        .UseUrls("http://localhost:4000");
                });
    }
}
Back to top
 
ASP.NET Core Startup Class
Path: /Startup.cs
The startup class configures the request pipeline of the application, dependency injection and how all requests are handled.

The below file contains configuration for:

The EF Core in memory database and mapping it to the DataContext class for dependency injection.
CORS (cross origin resource sharing) requests to the api.
Strongly typed access to app settings with the AppSettings class.
Enabling JWT Authentication.
Mapping the UserService class to the IUserService interface for dependency injection.
The Configure() method also creates a user in the db when the api starts for testing.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WebApi.Helpers;
using WebApi.Services;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using WebApi.Entities;
using System;

namespace WebApi
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // in memory database used for simplicity, change to a real db for production applications
            services.AddDbContext<DataContext>(x => x.UseInMemoryDatabase("TestDb"));
            services.AddCors();
            services.AddControllers().AddJsonOptions(x => x.JsonSerializerOptions.IgnoreNullValues = true);

            // configure strongly typed settings objects
            var appSettingsSection = Configuration.GetSection("AppSettings");
            services.Configure<AppSettings>(appSettingsSection);

            // configure jwt authentication
            var appSettings = appSettingsSection.Get<AppSettings>();
            var key = Encoding.ASCII.GetBytes(appSettings.Secret);
            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = false;
                x.SaveToken = true;
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                    ClockSkew = TimeSpan.Zero
                };
            });

            // configure DI for application services
            services.AddScoped<IUserService, UserService>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, DataContext context)
        {
            // add hardcoded test user to db on startup,  
            // plain text password is used for simplicity, hashed passwords should be used in production applications
            context.Users.Add(new User { FirstName = "Test", LastName = "User", Username = "test", Password = "test" });
            context.SaveChanges();

            app.UseRouting();

            // global cors policy
            app.UseCors(x => x
                .SetIsOriginAllowed(origin => true)
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials());

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(x => x.MapControllers());
        }
    }
}
Back to top
 
ASP.NET Core CSProj File
Path: /WebApi.csproj
The csproj (C# project) is an MSBuild based file that contains target framework and NuGet package dependency information for the application.

<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>netcoreapp3.1</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="3.1.4" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.InMemory" Version="3.1.4" />
    <PackageReference Include="System.IdentityModel.Tokens.Jwt" Version="6.5.1" />
  </ItemGroup>
</Project>
Back to top
 