using Marten;
using ServiceStack.Auth;

namespace ServiceStack.Authentication.Marten.Tests.Infrastructure
{
    public class DocumentStoreBuilder
    {
        public IDocumentStore Build()
        {
            var store = DocumentStore.For(opts =>
            {
                opts.Connection("host=localhost;username=marten;password=testpwd;database=marten-testing");
                opts.AuthRepository()
                    .UseAuth<UserAuth>()
                    .UseAuthDetails<UserAuthDetails>();
            });
            store.Advanced.Clean.CompletelyRemoveAll();
            return store;
        }
    }
}
