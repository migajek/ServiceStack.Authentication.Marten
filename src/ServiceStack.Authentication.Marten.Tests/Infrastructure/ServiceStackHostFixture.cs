using System;
using Funq;
using Marten;
using ServiceStack.Auth;
using ServiceStack.Testing;

namespace ServiceStack.Authentication.Marten.Tests.Infrastructure
{
    public class ServiceStackHostFixture: IDisposable
    {        
        private readonly ServiceStackHost _appHost;
        public int MaxLoginAttempts { get; } = 5;

        public ServiceStackHostFixture()
        {
            _appHost = new BasicAppHost().Init();
            var container = _appHost.GetContainer();

            container.Register<IDocumentStore>(c => new DocumentStoreBuilder().Build())
                .ReusedWithin(ReuseScope.Hierarchy);            

            container.Register<IUserAuthRepository>(c => new MartenAuthRepository(c.Resolve<IDocumentStore>()))
                .ReusedWithin(ReuseScope.Hierarchy);

            _appHost.Plugins.Add(new AuthFeature(() => new AuthUserSession(), new IAuthProvider[]
            {
                new CredentialsAuthProvider()
            })
            {
                MaxLoginAttempts = MaxLoginAttempts
            });
            
        }

        public void Dispose()
        {
            _appHost.Dispose();
        }
    }
}
