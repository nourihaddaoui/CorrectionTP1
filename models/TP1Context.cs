using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;

namespace TP1.models
{
    public class TP1Context : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<Password> Passwords { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite("Data Source=tp1.db");
        }
    }
}