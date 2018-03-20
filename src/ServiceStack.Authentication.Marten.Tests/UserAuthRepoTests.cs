using System;
using System.Linq;
using ServiceStack.Auth;
using ServiceStack.Testing;
using Xunit;

namespace ServiceStack.Authentication.Marten.Tests
{
    public class UserAuthRepoTests: IDisposable
    {
        private readonly IDisposable _appHost = new BasicAppHost().Init();        

        public void Dispose()
        {
            _appHost.Dispose();
        }

        [Fact]
        public void Can_create_user()
        {
            var sut = new UserAuthRepoFixtureBuilder()
                .Build();

            var user = new UserAuth()
            {
                UserName = "newuser",
                FirstName = "Mike"
            };

            var created = sut.CreateUserAuth(user, "12345");

            Assert.NotEqual(default(int), created.Id);            
        }

        [Fact]
        public void Can_create_multiple_users()
        {
            var sut = new UserAuthRepoFixtureBuilder()
                .WithUsers(
                    new UserAuth() {UserName = "Bob"},
                    new UserAuth() {UserName = "Alice"}
                )
                .Build();
            
            Assert.Equal(2, sut.Execute(session => session.Query<UserAuth>().Count()));
        }

        [Fact]
        public void Can_load_user_auth_by_username()
        {
            var sut = new UserAuthRepoFixtureBuilder()
                .WithUsers(new UserAuth()
                {
                    UserName = "NewUser",
                    Email = "newuser@example.com",
                    FirstName = "Mike"
                })
                .Build();

            var user = sut.GetUserAuthByUserName("newuser");

            Assert.NotNull(user);
            Assert.Equal("Mike", user.FirstName);
        }

        [Fact]
        public void Can_load_user_auth_by_email()
        {
            var sut = new UserAuthRepoFixtureBuilder()
                .WithUser(new UserAuth()
                {
                    UserName = "newuser",
                    Email = "newuser@Example.Com",
                    FirstName = "Mike"
                }, "123456")
                .Build();

            var user = sut.GetUserAuthByUserName("newuser@example.com");

            Assert.NotNull(user);
            Assert.Equal("Mike", user.FirstName);
        }              

        [Fact]
        public void Can_persist_preconfigured_permissions()
        {
            var sut = new UserAuthRepoFixtureBuilder()
                .WithUsers(
                    new UserAuth()
                    {
                        Id = 5,
                        UserName = "newuser",
                        Permissions = new[] {"perm1", "perm2", "perm3"}.ToList()
                    }, new UserAuth()
                    {
                        Id = 2,
                        UserName = "newuser2",
                        Permissions = new[] {"perm3"}.ToList()
                    }
                )
                .Build();

            var result = sut.HasPermission("5", "perm2");
            var invalidPermission = sut.HasPermission("5", "perm4");
            var invalidUserPermission = sut.HasPermission("2", "perm2");

            Assert.True(result);
            Assert.False(invalidPermission);
            Assert.False(invalidUserPermission);
        }
       
        [Fact]
        public void Can_unassign_permissions()
        {
            var sut = new UserAuthRepoFixtureBuilder()
                .WithUsers(
                    new UserAuth()
                    {
                        Id = 5,
                        UserName = "newuser",
                        Permissions = new[] {"perm1", "perm3"}.ToList()
                    }, new UserAuth()
                    {
                        Id = 2,
                        UserName = "newuser2",
                        Permissions = new[] {"perm3"}.ToList()
                    }
                )
                .Build();
            sut.AssignRoles("5", permissions: new[] {"perm3"});
            sut.UnAssignRoles("5", permissions: new[] {"perm2", "perm1"});
            sut.UnAssignRoles("2", permissions: new[] {"perm3"});

            var hasRemovedPermission1 = sut.HasPermission("5", "perm2");
            var hasRemovedPermission2 = sut.HasPermission("5", "perm1");
            var hasUnremovedPermission = sut.HasPermission("5", "perm3");

            Assert.True(hasUnremovedPermission);
            Assert.False(hasRemovedPermission1);
            Assert.False(hasRemovedPermission2);

            Assert.False(sut.HasPermission("2", "perm3"));
        }
    }
}
