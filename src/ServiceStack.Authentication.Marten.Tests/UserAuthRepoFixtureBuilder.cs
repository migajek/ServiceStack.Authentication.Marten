using System;
using System.Collections.Generic;
using Marten;
using NSubstitute;
using ServiceStack.Auth;
using ServiceStack.Authentication.Marten.Tests.Infrastructure;

namespace ServiceStack.Authentication.Marten.Tests
{
    public class UserAuthRepoFixtureBuilder : IDisposable
    {
        private readonly IDocumentStore _store;
        private readonly IDictionary<UserAuth, string> _users = new Dictionary<UserAuth, string>();
        private readonly IHashProvider _hashMock;        

        public UserAuthRepoFixtureBuilder()
        {
            _store = new DocumentStoreBuilder().Build();
            _hashMock = PrepareHashProvider();
        }

        private IHashProvider PrepareHashProvider()
        {
            var hashMock = Substitute.For<IHashProvider>();

            {
                string hash;
                string salt;
                hashMock
                    .WhenForAnyArgs(x => x.GetHashAndSaltString(Arg.Any<string>(), out hash, out salt))
                    .Do(ci =>
                    {
                        // the hash is just a plain password
                        ci[1] = ci.Args()[0].ToString();
                        ci[2] = "salt";
                    });
            }

            hashMock
                .VerifyHashString(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
                .Returns(ci =>
                {
                    var password = ci.Args()[0].ToString();
                    var hash = ci.Args()[1];
                    var salt = ci.Args()[2];
                    return password.Equals(hash) && salt.ToString() == "salt";
                });
            return hashMock;
        }
        
        public void Dispose()
        {
            _store.Dispose();
        }
      
        public MartenAuthRepository<UserAuth, UserAuthDetails> Build()
        {
            var sut = new MartenAuthRepository<UserAuth, UserAuthDetails>(_store) {HashProvider = _hashMock};
            _users.Each(kv => sut.CreateUserAuth(kv.Key, kv.Value));
            return sut;
        }

        public UserAuthRepoFixtureBuilder WithUsers(params UserAuth[] userAuths)
        {
            userAuths.Each(x => WithUser(x, "none"));
            return this;
        }

        public UserAuthRepoFixtureBuilder WithUser(UserAuth user, string password)
        {
            _users[user] = password;
            return this;
        }
    }
}