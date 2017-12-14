using System.Linq;
using System.Text;
using ServiceStack.Auth;

namespace ServiceStack.Authentication.Marten.Tests
{
    internal class HashProviderMock : IHashProvider
    {
        private const string SaltValue = "salt";
        private static readonly byte[] SaltBytes = Encoding.UTF8.GetBytes((string) SaltValue);

        public void GetHashAndSalt(byte[] data, out byte[] hash, out byte[] salt)
        {
            hash = data;
            salt = SaltBytes;
        }

        public void GetHashAndSaltString(string data, out string hash, out string salt)
        {
            hash = data;
            salt = SaltValue;
        }

        public bool VerifyHash(byte[] data, byte[] hash, byte[] salt)
        {
            return data.SequenceEqual(hash) && salt.SequenceEqual(SaltBytes);
        }

        public bool VerifyHashString(string data, string hash, string salt)
        {
            return data.Equals(hash) && salt.Equals(SaltValue);
        }
    }
}