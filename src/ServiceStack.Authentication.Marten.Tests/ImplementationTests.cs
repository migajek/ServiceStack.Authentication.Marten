using System;
using Marten.Linq;
using ServiceStack.Auth;
using Xunit;

namespace ServiceStack.Authentication.Marten.Tests
{
    public class ImplementationTests
    {
        [Fact]
        public void Permission_query_uses_psql_json_contains()
        {
            var sut = new UserAuthRepoFixtureBuilder()
                .Build();

            sut.Execute(session => {
                var command = session.Query<UserAuth>()
                    .Where(x => x.Permissions.Contains("perm3") && x.Id == 2)
                    .ToCommand(FetchType.Any);

                // uses JSONb contains operator
                Assert.Contains("@>", command.CommandText);
            });
        }

        [Fact]
        public void Get_user_by_name_uses_separate_field()
        {
            var sut = new UserAuthRepoFixtureBuilder()                
                .Build();

            sut.Execute(session =>
            {
                var command = session.Query<UserAuth>()
                    .Where(x => x.UserName.Equals("bob", StringComparison.CurrentCultureIgnoreCase))
                    .ToCommand(FetchType.FetchOne);             
                
                // does not operate on JSONb
                Assert.DoesNotContain(">", command.CommandText);
                // matches d.user_name ILIKE 
                Assert.Matches(@"\w+\.user_name\s+ILIKE", command.CommandText);
            });
        }

    }
}
