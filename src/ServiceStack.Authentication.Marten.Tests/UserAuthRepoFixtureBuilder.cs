using System;
using System.Collections.Generic;
using Marten;
using ServiceStack.Auth;
using ServiceStack.Authentication.Marten.Tests.Infrastructure;

namespace ServiceStack.Authentication.Marten.Tests
{    
    public class UserAuthRepoFixtureBuilder : IDisposable
    {
        private readonly IDocumentStore _store;
        private readonly IDictionary<UserAuth, string> _users = new Dictionary<UserAuth, string>();           

        public UserAuthRepoFixtureBuilder()
        {
            _store = new DocumentStoreBuilder().Build();        
        }
        
        public void Dispose()
        {
            _store.Dispose();
        }
      
        public MartenAuthRepository<UserAuth, UserAuthDetails> Build()
        {
            var sut = new MartenAuthRepository<UserAuth, UserAuthDetails>(_store, new HashProviderMock());
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