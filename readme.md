# ServiceStack.Authentication.Marten

This project provides an implementation of [ServiceStack's](http://servicestack.net) ``UserAuthRepository`` using [Marten](http://jasperfx.github.io/marten/getting_started/) for storage.


## Key features

* supports .NET 4.6 and .NET Core
* it's generic: supports custom implementations of ``UserAuth`` and ``UserAuthDetails``
* handles user & role/permission management (implements ``IUserAuthRepository, IManageRoles``)
* handles API Key management (implements ``IManageApiKeys``)

## Release Notes
 * 0.6.0 updated hashing to reflect changes in ServiceStack 5. Extacted public CreateUser method to be used with event store projections
 * 0.5.0 implemented ``IManageApiKeys``
 * 0.4.0 support for ServiceStack >= 5.0
 * 0.3.0 support for Marten >= 2.0

## Getting started

1. install it via nuget ``Install-Package ServiceStack.Authentication.Marten``
2. when configuring Marten, use an ``AuthRepository()`` extension method to configure the storage for both ``UserAuth`` and ``UserAuthDetails`` types (or your own implementations, when using generic version)
   
   ```csharp
   DocumentStore.For(opts =>
            {      
                opts.AuthRepository()
                    .UseAuth<UserAuth>()
                    .UseAuthDetails<UserAuthDetails>();
            });
   ```
3. register the auth repository in the container    
    ```csharp
    // ex.: container.Register<IDocumentStore>(c => new DocumentStoreBuilder().Build())
    //            .ReusedWithin(ReuseScope.Hierarchy);
    container.RegisterAutoWiredAs<MartenAuthRepository, IUserAuthRepository>()
                .ReusedWithin(ReuseScope.Hierarchy);
    ```
    

## Missing features / roadmap
* ~no support for Marten as Event Store (yet ..)~ provide demo of Event Store approach
* optional ``StoreChanges`` call when re-using IDocumentSession
* full test coverage
