# ServiceStack.Authentication.Marten

This repository provides an implementation of [ServiceStack's](servicestack.net) ``UserAuthRepository`` using [Marten](jasperfx.github.io/marten/getting_started/) for storage.


## Key features

* supports .NET 4.6 and .NET Core
* handles user & role/permission management (implements ``IUserAuthRepository, IManageRoles``)
* it's generic: supports custom implementations of ``UserAuth`` and ``UserAuthDetails``
* can manage the ``IDocumentSession`` on it's own, or reuse the request-scoped session

## Getting started

1. install it via nuget ``Install-Package ServiceStack.Authentication.Marten``
2. when configuring Marten, use an ``AuthRepository()`` extension method to configure the storage for both ``UserAuth`` and ``UserAuthDetails`` types (or your own implementations, when using generic version)
   ```
   DocumentStore.For(opts =>
            {      
                opts.AuthRepository()
                    .UseAuth<UserAuth>()
                    .UseAuthDetails<UserAuthDetails>();
            });
   ```
3. register the auth repository in the container
    * either provide ``IDocumentStore`` to constructor, to let it handle the session on it's own:
    ```
    // ex.: container.Register<IDocumentStore>(c => new DocumentStoreBuilder().Build())
    //            .ReusedWithin(ReuseScope.Hierarchy);
    container.Register<IUserAuthRepository>(c => new MartenAuthRepository(c.Resolve<IDocumentStore>()))
                .ReusedWithin(ReuseScope.Hierarchy);
    ```
    
    * or provide ``IDocumentSession``, to reuse per-request session
    ```
    // ex. container.Register(c => c.Resolve<IDocumentStore>().OpenSession())
    //            .ReusedWithin(ReuseScope.Request);
    container.Register<IUserAuthRepository>(c => new MartenAuthRepository(c.Resolve<IDocumentSession>()))
                .ReusedWithin(ReuseScope.Request);
    ```

## Missing features / roadmap
* no support for Marten as Event Store (yet ..)
* optional ``StoreChanges`` call when re-using IDocumentSession
* full test coverage