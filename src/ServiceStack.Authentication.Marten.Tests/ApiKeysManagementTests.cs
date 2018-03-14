using System.Linq;
using ServiceStack.Auth;
using Xunit;

namespace ServiceStack.Authentication.Marten.Tests
{
    public class ApiKeysManagementTests
    {
        [Fact]
        public void Can_manage_api_keys()
        {
            var sut = new UserAuthRepoFixtureBuilder()
                .WithApiKeys(new ApiKey()
                {
                    UserAuthId = "4",
                    Id = "foo-key1",                    
                },
                new ApiKey()
                {
                    UserAuthId = "4",
                    Id = "foo-keyy2"
                },
                new ApiKey()
                {
                    UserAuthId = "5",
                    Id = "foobarkey1"
                })
                .Build() as IManageApiKeys;

            Assert.True(sut.ApiKeyExists("foo-key1"));
            Assert.True(sut.ApiKeyExists("foobarkey1"));

            Assert.Equal("5", sut.GetApiKey("foobarkey1").UserAuthId);

            Assert.Equal(new[] {"foo-key1", "foo-keyy2"}, sut.GetUserApiKeys("4").Select(x => x.Id));
        }
    }
}
