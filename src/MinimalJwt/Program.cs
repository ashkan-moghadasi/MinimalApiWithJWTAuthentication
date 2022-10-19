using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MinimalJwt.Models;
using MinimalJwt.Services;

var builder = WebApplication.CreateBuilder(args);

//Add Authentication and Authorization
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new()
        {
            ValidateActor = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddAuthorization(o =>
    o.AddPolicy("AdminsOnly", b =>
        {
            b.AuthenticationSchemes = new[] { JwtBearerDefaults.AuthenticationScheme };
            b.RequireClaim(ClaimTypes.Role, "Administrator");
        }
    )
);

// Add Dependency Injection Services
builder.Services
    .AddEndpointsApiExplorer()
    .AddSingleton<IMovieService, MovieService>()
    .AddSingleton<IUserService, UserService>();

//Add Swagger with GWT Config
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Name = "Authorization",
        Description = "Bearer Authentication with JWT Token",
        Type = SecuritySchemeType.Http
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            },
            new List<string>()
        }
    });
});
var app = builder.Build();

app.UseSwagger();
app.UseAuthorization();
app.UseAuthentication();

app.MapGet("/", () => "Hello World!");

app.MapPost("/login", Login)
    .AllowAnonymous();

app.MapPost("/create",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator")]
    (Movie movie, IMovieService movieService) => Create(movie, movieService));

app.MapPut("/update",Update)
    .RequireAuthorization("AdminsOnly");

app.MapDelete("/delete",Delete)
    .RequireAuthorization("AdminsOnly");
    


app.MapGet("/get",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "Administrator,Standard")]
    (int id, IMovieService movieService) => Get(id, movieService)
);

app.MapGet("/list",
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    (IMovieService service)=> List(service))
    .RequireAuthorization();

IResult Login(UserLogin userLogin, IUserService userService)
{
    if (userLogin.UserName.IsNullOrEmpty() || userLogin.Password.IsNullOrEmpty())
    {
        return Results.BadRequest("User name or password is empty");
    }

    var loggedInUser = userService.Get(userLogin);
    if (loggedInUser is null) return Results.NotFound("User Not Found");
    var claims = new Claim[]
    {
        new Claim(ClaimTypes.GivenName, loggedInUser.GivenName),
        new Claim(ClaimTypes.Surname, loggedInUser.Surname),
        new Claim(ClaimTypes.Email, loggedInUser.EmailAddress),
        new Claim(ClaimTypes.NameIdentifier, loggedInUser.Username),
        new Claim(ClaimTypes.Role, loggedInUser.Role)
    };
    var token = new JwtSecurityToken(
        issuer: builder.Configuration["Jwt:Issuer"],
        audience: builder.Configuration["Jwt:Audience"],
        claims: claims,
        notBefore: DateTime.UtcNow,
        expires: DateTime.UtcNow.AddDays(60),
        signingCredentials: new SigningCredentials(
            key: new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:key"])),
            algorithm: SecurityAlgorithms.HmacSha256)
    );
    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
    return Results.Ok(tokenString);
}

IResult Create(Movie movie, IMovieService service)
{
    var newMovie = service.Create(movie);
    return Results.Ok(movie);
}

IResult Update(Movie oldMovie, IMovieService service)
{
    var newMovie = service.Update(oldMovie);
    return newMovie is null ? Results.NotFound("Movie Not Fount") : Results.Ok(newMovie);
}

IResult Delete(int id, IMovieService movieService)
{
    var deleteResult = movieService.Delete(id);
    return !deleteResult ? Results.BadRequest("Movie Not Fount") : Results.Ok();
}

IResult Get(int id, IMovieService movieService)
{
    var result = movieService.Get(id);
    return result is null ? Results.NotFound("Movie Not Fount") : Results.Ok(result);
}

IResult List(IMovieService movieService)
{
    return Results.Ok(movieService.List());
}

app.UseSwaggerUI();
app.Run();