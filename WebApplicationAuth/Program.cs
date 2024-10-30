using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebApplicationAuth.Controllers.Identity;
using WebApplicationAuth.Entities;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthorizationBuilder();
builder.Services.AddIdentity<AppUser, AppRole>()
        .AddUserStore<CustomUserStore>()
        .AddRoleStore<CustomRoleStore>()
        .AddRoles<AppRole>()
        .AddDefaultTokenProviders();
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(connectionString));
builder.Services.AddCors(
    options => options.AddPolicy(
        "wasm",
        policy => policy.WithOrigins([builder.Configuration["BackendUrl"] ?? "https://localhost:7082", 
            builder.Configuration["FrontendUrl"] ?? "https://localhost:7133"])
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials()));
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors("wasm");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
