using Marten;

namespace ServiceStack.Authentication.Marten
{
    public static class MartenAuthRepositoryConfigExtension
    {
        public static IMartenAuthRepositoryConfig AuthRepository(this StoreOptions storeOptions)
        {
            return new MartenAuthRepositoryConfig(storeOptions);
        }        
    }
}