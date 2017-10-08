namespace TP1.models
{
    public class Password
    {
        public int PasswordId { get; set; }
        public string Tag { get; set; }
        public string SavedPassword { get; set; }

        public int UserId { get; set; }
        public User User { get; set; }
    }
}