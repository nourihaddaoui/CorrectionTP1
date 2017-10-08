using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.EntityFrameworkCore;
using TP1.models;

namespace TP1
{
    public class TP1
    {
        public void InterpretCommand(string[] command){
            if(command.Length == 0){
                Console.WriteLine("Sorry you didn't fill the parameters");
                return;
            }
            switch (command[0])
            {
                case "-r":
                    if(command.Length == 3){
                        if(Register(command[1], command[2])){
                            System.Console.WriteLine("OK");
                        }else{System.Console.WriteLine("Error in user registration");

                        }
                    }else{
                        Console.WriteLine("Sorry you didn't fill the parameters");
                    }
                    break;
                case "-a":
                    if(command.Length == 5){
                        byte[] key = Connect(command[1], command[2]);
                        if(key != null){
                            AddPassword(command[1], key, command[3], command[4]);
                        }else{
                            Console.WriteLine("Wrong password");
                        }
                    }else{
                        Console.WriteLine("Sorry you didn't fill the parameters");
                    }
                    break;
                case "-g":
                    if(command.Length == 4){
                        byte[] key = Connect(command[1], command[2]);
                        if(key != null){
                            ShowPassword(command[1], key, command[3]);
                        }else{
                            Console.WriteLine("Wrong password");
                        }
                    }else{
                        Console.WriteLine("Sorry you didn't fill the parameters");
                    }
                    break;
                case "-d":
                    if(command.Length == 4){
                        if(Connect(command[1], command[2]) != null){
                            DeletePassword(command[1], command[3]);
                        }else{
                            Console.WriteLine("Wrong password");
                        }
                    }else{
                        Console.WriteLine("Sorry you didn't fill the parameters");
                    }
                    break;
                case "-t":
                    if(command.Length == 2){
                        TestHash(command[1]);
                    }else if(command.Length == 3){
                        TestPassword(command[1],command[2]);
                    }else{
                        Console.WriteLine("Sorry you didn't fill the parameters");
                    }
                    break;
                default:
                    Console.WriteLine("Sorry action not recognized");
                    break;
            }
        }

        public byte[] Connect(string username, string masterPassword){
            using (var db = new TP1Context())
            {
                var data = from u in db.Users where u.Username == username select u;
                User user = data.FirstOrDefault();

                if(user == null){
                    return null;
                }
                
                using(var sha256 = SHA256.Create())  
                {  
                    byte[] salt = Convert.FromBase64String(user.Salt);
                    byte[] passwordBytes = System.Text.Encoding.Unicode.GetBytes(masterPassword);
                        
                    byte[] encodedBytes = new byte[passwordBytes.Length + salt.Length];
                    passwordBytes.CopyTo(encodedBytes, 0);
                    salt.CopyTo(encodedBytes,passwordBytes.Length);

                    var hashedBytes = sha256.ComputeHash(encodedBytes);  
                    string encodedTxt = Convert.ToBase64String(encodedBytes);

                    if(encodedTxt != user.Password){
                        return null;
                    }

                    return KeyDerivation.Pbkdf2(masterPassword, salt, KeyDerivationPrf.HMACSHA256, 10000, 256/8);
                }  
            }
        }

        public bool Register(string username, string masterPassword){
            using (var db = new TP1Context())
            {
                var data = from u in db.Users where u.Username == username select u;
                User user = data.FirstOrDefault();

                if(user != null){
                    System.Console.WriteLine("User already exists");
                    return false;
                }
                
                byte[] salt = new byte[128 / 8];  

                using(var keyGenerator = RandomNumberGenerator.Create())  
                {  
                    keyGenerator.GetBytes(salt);  
                    string encodedSalt = Convert.ToBase64String(salt);
                    using(var sha256 = SHA256.Create())  
                    {  
                        // Send a sample text to hash.  
                        byte[] passwordBytes = System.Text.Encoding.Unicode.GetBytes(masterPassword);
                        
                        byte[] encodedBytes = new byte[passwordBytes.Length + salt.Length];
                        passwordBytes.CopyTo(encodedBytes, 0);
                        salt.CopyTo(encodedBytes,passwordBytes.Length);

                        var hashedBytes = sha256.ComputeHash(encodedBytes);  
                        string encodedTxt = Convert.ToBase64String(encodedBytes);
                        user = new User(){
                            Username= username,
                            Password= encodedTxt,
                            Salt=encodedSalt,
                        };
                        db.Users.Add(user);
                        return db.SaveChanges() == 1;
                    }  
                }  
            }
        }

        public void AddPassword(string username, byte[] encryptionKey, string tag, string password){
            using (var db = new TP1Context())
            {   
                var data = from u in db.Users where u.Username == username select u;
                User user = data.FirstOrDefault();
                
                using (var aesAlg = Aes.Create())
                {
                    using (var encryptor = aesAlg.CreateEncryptor(encryptionKey, aesAlg.IV))
                    {
                        using (var msEncrypt = new MemoryStream())
                        {
                            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                            using (var swEncrypt = new StreamWriter(csEncrypt))
                            {
                                swEncrypt.Write(password);
                            }

                            var iv = aesAlg.IV;

                            var decryptedContent = msEncrypt.ToArray();

                            var result = new byte[iv.Length + decryptedContent.Length];

                            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                            Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

                            string base64Password = Convert.ToBase64String(result);
                            db.Passwords.Add(new Password(){
                                SavedPassword = base64Password,
                                User = user,
                                UserId = user.UserID,
                                Tag = tag
                            });

                            if(db.SaveChanges() == 1){
                                System.Console.WriteLine("OK");
                            }else{
                                System.Console.WriteLine("Error id DB save");
                            }
                        }
                    }
                }
            }
        }

        public void ShowPassword(string username, byte[] encryptionKey, string tag){
            using (var db = new TP1Context())
            {   
                var data = db.Users.Include(u => u.SavedPassword).Where(u => u.Username == username);
                User user = data.FirstOrDefault();
                
                if(user == null || user.SavedPassword == null){
                    System.Console.WriteLine("Password does not exist");
                    return;
                }

                Password pwd = user.SavedPassword.Where(p => p.Tag == tag).FirstOrDefault();

                if(pwd == null){
                    System.Console.WriteLine("Password does not exist");
                    return;
                }

                var fullCipher = Convert.FromBase64String(pwd.SavedPassword);

                var iv = new byte[16];
                var cipher = new byte[fullCipher.Length - 16];

                Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, iv.Length);

                using (var aesAlg = Aes.Create())
                {
                    using (var decryptor = aesAlg.CreateDecryptor(encryptionKey, iv))
                    {
                        string result;
                        using (var msDecrypt = new MemoryStream(cipher))
                        {
                            using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                            {
                                using (var srDecrypt = new StreamReader(csDecrypt))
                                {
                                    result = srDecrypt.ReadToEnd();
                                }
                            }
                        }

                        System.Console.WriteLine(result);
                    }
                }
            }
        }

        public void DeletePassword(string username, string tag){
            using (var db = new TP1Context())
            {   
                var data = db.Users.Include(u => u.SavedPassword).Where(u => u.Username == username);
                User user = data.FirstOrDefault();
                
                if(user == null || user.SavedPassword == null){
                    System.Console.WriteLine("Password does not exist");
                    return;
                }

                Password pwd = user.SavedPassword.Where(p => p.Tag == tag).FirstOrDefault();

                if(pwd == null){
                    System.Console.WriteLine("Password does not exist");
                    return;
                }

                db.Passwords.Remove(pwd);
                db.SaveChanges();
                System.Console.WriteLine("OK");
            }
        }

        public void TestHash(string username){
            using (var db = new TP1Context())
            {   
                var data = db.Users.Where(u => u.Username == username);
                User user = data.FirstOrDefault();
                
                if(user == null){
                    System.Console.WriteLine("User does not exist");
                }
                
                System.Console.WriteLine("{0}:{1}",user.Salt,user.Password);
            }
        }

        public void TestPassword(string username, string tag){
            using (var db = new TP1Context())
            {   
                var data = db.Users.Include(u => u.SavedPassword).Where(u => u.Username == username);
                User user = data.FirstOrDefault();
                
                if(user == null || user.SavedPassword == null){
                    System.Console.WriteLine("Password does not exist");
                    return;
                }
                
                Password pwd = user.SavedPassword.Where(p => p.Tag == tag).FirstOrDefault();

                if(pwd == null){
                    System.Console.WriteLine("Password does not exist");
                    return;
                }
                System.Console.WriteLine(pwd.SavedPassword);
            }
        }
    }
}