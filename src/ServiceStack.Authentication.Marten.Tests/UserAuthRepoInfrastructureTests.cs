using System;
using ServiceStack.Auth;
using ServiceStack.Authentication.Marten.Tests.Infrastructure;
using Xunit;

namespace ServiceStack.Authentication.Marten.Tests
{
    public class UserAuthRepoInfrastructureTests: IClassFixture<ServiceStackHostFixture>
    {
        [Fact]
        public void Can_record_invalid_auth_attempts()
        {
            var sut = new UserAuthRepoFixtureBuilder()
                .WithUser(new UserAuth() { UserName = "Bob" }, "bob2")
                .Build();

            IUserAuth user;
            // invalid password
            var result = sut.TryAuthenticate("bob", "wrongpassword", out user);

            var user2 = sut.GetUserAuthByUserName("bob");

            Assert.False(result);
            Assert.Null(user);

            Assert.Equal(1, user2.InvalidLoginAttempts);
            Assert.True((DateTime.UtcNow - user2.LastLoginAttempt.Value).TotalSeconds <= 1);
        }
    }
}
