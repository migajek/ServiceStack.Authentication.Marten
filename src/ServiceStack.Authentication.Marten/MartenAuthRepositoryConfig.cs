using Marten;
using Marten.Schema;
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
                .Duplicate(x => x.UserAuthId)
                .Index(x => x.UserAuthId);
            return this;
        }

        public IMartenAuthRepositoryConfig UseAuth<TUserAuth>() where TUserAuth : IUserAuth
        {
            _storeOptions.Schema.For<TUserAuth>()
                .Duplicate(x => x.Email)
                .Duplicate(x => x.UserName)
                .Index(x => x.Email, def => def.IsUnique = true)
                .Index(x => x.UserName, def => def.IsUnique = true);
            return this;
        }
    }
}