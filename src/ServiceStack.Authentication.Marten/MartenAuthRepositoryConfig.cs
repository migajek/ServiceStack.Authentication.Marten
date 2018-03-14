using Marten;
using ServiceStack.Auth;

namespace ServiceStack.Authentication.Marten
{
    public interface IMartenAuthRepositoryConfig
    {
        IMartenAuthRepositoryConfig UseAuthDetails<TAuthDetails>()
            where TAuthDetails : IUserAuthDetails;

        IMartenAuthRepositoryConfig UseAuth<TUserAuth>()
            where TUserAuth : IUserAuth;
    }

    class MartenAuthRepositoryConfig : IMartenAuthRepositoryConfig        
    {
        private readonly StoreOptions _storeOptions;

        public MartenAuthRepositoryConfig(StoreOptions storeOptions)
        {
            _storeOptions = storeOptions;
        }

        public IMartenAuthRepositoryConfig UseAuthDetails<TAuthDetails>() where TAuthDetails : IUserAuthDetails
        {
            _storeOptions.Schema.For<TAuthDetails>()
                .Duplicate(x => x.UserAuthId);                
            return this;
        }

        public IMartenAuthRepositoryConfig UseAuth<TUserAuth>() where TUserAuth : IUserAuth
        {
            _storeOptions.Schema.For<TUserAuth>()
                .Duplicate(x => x.Email, configure: idx => idx.IsUnique = true)
                .Duplicate(x => x.UserName, configure: idx => idx.IsUnique = true);
            return this;
        }

        public IMartenAuthRepositoryConfig ConfigureApiKeys()
        {
            _storeOptions.Schema.For<ApiKey>()
                .Duplicate(x => x.UserAuthId);

            return this;
        }
    }
}