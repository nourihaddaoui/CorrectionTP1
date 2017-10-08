using System.Collections.Generic;

namespace TP1.models
{
    public class User
    {
        public int UserID { get; set; }
        public string Username { get; set; }
        public string Salt { get; set; }
        public string Password { get; set; }
        public List<Password> SavedPassword { get; set; }
    }
}