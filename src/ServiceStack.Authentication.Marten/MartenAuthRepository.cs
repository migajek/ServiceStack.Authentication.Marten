using System;
using System.Linq;
using System.Collections.Generic;
using ServiceStack.Auth;
using Marten;

namespace ServiceStack.Authentication.Marten
{
    public interface IMartenAuthRepository : IUserAuthRepository
    {
        IUserAuth CreateUserAuth(IUserAuth newUser, string passwordHash, string authDigest, string salt);
    }

    public class MartenAuthRepository : MartenAuthRepository<UserAuth, UserAuthDetails>
    {
        public MartenAuthRepository(IDocumentStore documentStore) : base(documentStore)
        {
        }
    }

    /// <summary>
    /// Auth repository to be used embedded in a custom projection. It doesn't manage own DocumentSession,
    /// only relies on DocumentOperations passed from outside - i.e. from projection
    /// </summary>
    /// <typeparam name="TUserAuth"></typeparam>
    /// <typeparam name="TUserAuthDetails"></typeparam>
    public class
        MartenEmbeddedAuthRepository<TUserAuth, TUserAuthDetails> : MartenAuthRepositoryBase<TUserAuth,
            TUserAuthDetails>
        where TUserAuth : class, IUserAuth
        where TUserAuthDetails : class, IUserAuthDetails
    {
        private readonly IDocumentOperations _documentOperations;

        public MartenEmbeddedAuthRepository(IDocumentOperations documentOperations)
        {
            _documentOperations = documentOperations;
        }

        internal override void Execute(Action<IDocumentOperations> fn) => fn(_documentOperations);

        internal override T Execute<T>(Func<IDocumentOperations, T> fn) => fn(_documentOperations);
    }

    /// <summary>
    /// Regular, stand-alone Marten auth repository
    /// </summary>
    /// <typeparam name="TUserAuth"></typeparam>
    /// <typeparam name="TUserAuthDetails"></typeparam>
    public class
        MartenAuthRepository<TUserAuth, TUserAuthDetails> : MartenAuthRepositoryBase<TUserAuth, TUserAuthDetails>
        where TUserAuth : class, IUserAuth
        where TUserAuthDetails : class, IUserAuthDetails 
    {
        private readonly IDocumentStore _documentStore;

        public MartenAuthRepository(IDocumentStore documentStore)
        {
            _documentStore = documentStore;
        }

        internal override void Execute(Action<IDocumentOperations> fn)
        {
            using var session = GetDocumentSession();
            fn(session);
            session.SaveChanges();
        }

        internal override T Execute<T>(Func<IDocumentOperations, T> fn)
        {
            using var session = GetDocumentSession();
            var result = fn(session);
            session.SaveChanges();
            return result;
        }

        private IDocumentSession GetDocumentSession() => _documentStore.IdentitySession();
    }

    public abstract class MartenAuthRepositoryBase<TUserAuth, TUserAuthDetails> : IMartenAuthRepository,  IUserAuthRepository, IManageRoles, IManageApiKeys
        where TUserAuth : class, IUserAuth
        where TUserAuthDetails : class, IUserAuthDetails
    {

        internal abstract void Execute(Action<IDocumentOperations> fn);

        internal abstract T Execute<T>(Func<IDocumentOperations, T> fn);
        public void LoadUserAuth(IAuthSession session, IAuthTokens tokens)
        {
            if (session == null)
                throw new ArgumentNullException(nameof(session));

            var userAuth = GetUserAuth(session, tokens);
            LoadUserAuth(session, (TUserAuth)userAuth);
        }

        private void LoadUserAuth(IAuthSession session, IUserAuth userAuth)
        {
            session.PopulateSession(userAuth, this);
        }

        public virtual IUserAuth GetUserAuth(string userAuthId)
        {
            return Execute(session => session.Load<TUserAuth>(int.Parse(userAuthId)));
        }

        public void SaveUserAuth(IAuthSession authSession)
        {
            if (authSession == null)
                throw new ArgumentNullException(nameof(authSession));

            Execute(session =>
            {
                var userAuth = !authSession.UserAuthId.IsNullOrEmpty()
                    ? session.Load<TUserAuth>(int.Parse(authSession.UserAuthId))
                    : authSession.ConvertTo<TUserAuth>();

                if (userAuth.Id == default(int) && !authSession.UserAuthId.IsNullOrEmpty())
                    userAuth.Id = int.Parse(authSession.UserAuthId);

                userAuth.ModifiedDate = DateTime.UtcNow;
                if (userAuth.CreatedDate == default(DateTime))
                    userAuth.CreatedDate = userAuth.ModifiedDate;

                session.Store(userAuth);
            });
        }

        public List<IUserAuthDetails> GetUserAuthDetails(string userAuthId)
        {
            var id = int.Parse(userAuthId);
            return Execute(session =>
            {
                return session.Query<TUserAuthDetails>()
                    .Where(q => q.UserAuthId == id)
                    .OrderBy(x => x.ModifiedDate)
                    .ToList()
                    .Cast<IUserAuthDetails>()
                    .ToList();
            });
        }

        public IUserAuthDetails CreateOrMergeAuthSession(IAuthSession authSession, IAuthTokens tokens)
        {
            TUserAuth userAuth = (TUserAuth) GetUserAuth(authSession, tokens)
                                 ?? typeof (TUserAuth).CreateInstance<TUserAuth>();

            return Execute(session =>
            {
                var authDetails =
                    session.Query<TUserAuthDetails>()
                        .FirstOrDefault(q => q.Provider == tokens.Provider && q.UserId == tokens.UserId);

                if (authDetails == null)
                {
                    authDetails = typeof (TUserAuthDetails).CreateInstance<TUserAuthDetails>();
                    authDetails.Provider = tokens.Provider;
                    authDetails.UserId = tokens.UserId;
                }

                authDetails.PopulateMissing(tokens, overwriteReserved: true);
                userAuth.PopulateMissingExtended(authDetails);

                userAuth.ModifiedDate = DateTime.UtcNow;
                if (userAuth.CreatedDate == default(DateTime))
                    userAuth.CreatedDate = userAuth.ModifiedDate;

                session.Store(userAuth);

                authDetails.UserAuthId = userAuth.Id;

                authDetails.ModifiedDate = userAuth.ModifiedDate;
                if (authDetails.CreatedDate == default(DateTime))
                    authDetails.CreatedDate = userAuth.ModifiedDate;

                session.Store(authDetails);
                return authDetails;
            });
        }

        public IUserAuth GetUserAuth(IAuthSession authSession, IAuthTokens tokens)
        {
            if (!authSession.UserAuthId.IsNullOrEmpty())
            {
                var userAuth = GetUserAuth(authSession.UserAuthId);
                if (userAuth != null)
                    return userAuth;
            }
            if (!authSession.UserAuthName.IsNullOrEmpty())
            {
                var userAuth = GetUserAuthByUserName(authSession.UserAuthName);
                if (userAuth != null)
                    return userAuth;
            }

            if (tokens == null || tokens.Provider.IsNullOrEmpty() || tokens.UserId.IsNullOrEmpty())
                return null;

            return Execute(session =>
            {
                var oAuthProvider =
                    session.Query<TUserAuthDetails>()
                        .FirstOrDefault(q => q.Provider == tokens.Provider && q.UserId == tokens.UserId);

                if (oAuthProvider != null)
                    return session.Load<TUserAuth>(oAuthProvider.UserAuthId);
                return null;
            });
        }

        public IUserAuth GetUserAuthByUserName(string userNameOrEmail)
        {
            if (userNameOrEmail == null)
                return null;
            return Execute(session => GetUserAuthByUserName(session, userNameOrEmail));
        }

        public TUserAuth GetUserAuthByUserName(IDocumentOperations session, string userNameOrEmail)
        {
            var isEmail = userNameOrEmail.Contains("@");
            return isEmail
                ? session.Query<TUserAuth>()
                    .SingleOrDefault(x => x.Email.Equals(userNameOrEmail, StringComparison.CurrentCultureIgnoreCase))
                : session
                    .Query<TUserAuth>()
                    .SingleOrDefault(x => x.UserName.Equals(userNameOrEmail, StringComparison.CurrentCultureIgnoreCase));
        }

        public void SaveUserAuth(IUserAuth userAuth)
        {
            if (userAuth == null)
                throw new ArgumentNullException(nameof(userAuth));

            Execute(session =>
            {
                SaveUserAuth(session, userAuth);
            });
        }

        private void SaveUserAuth(IDocumentOperations session, IUserAuth userAuth)
        {
            userAuth.ModifiedDate = DateTime.UtcNow;
            if (userAuth.CreatedDate == default(DateTime))
                userAuth.CreatedDate = userAuth.ModifiedDate;

            session.Store((TUserAuth) userAuth);
        }

        public bool TryAuthenticate(string userName, string password, out IUserAuth userAuth)
        {
            userAuth = GetUserAuthByUserName(userName);
            if (userAuth == null)
                return false;

            if (userAuth.VerifyPassword(password, out var needsRehash))
            {
                this.RecordSuccessfulLogin(userAuth, needsRehash, password);
                return true;
            }

            this.RecordInvalidLoginAttempt(userAuth);

            userAuth = null;
            return false;
        }

        public bool TryAuthenticate(Dictionary<string, string> digestHeaders, string privateKey, int nonceTimeOut,
            string sequence,
            out IUserAuth userAuth)
        {
            userAuth = GetUserAuthByUserName(digestHeaders["username"]);
            if (userAuth == null)
                return false;

            if (userAuth.VerifyDigestAuth(digestHeaders, privateKey, nonceTimeOut, sequence))
            {
                this.RecordSuccessfulLogin(userAuth);
                return true;
            }

            this.RecordInvalidLoginAttempt(userAuth);

            userAuth = null;
            return false;
        }

        protected virtual void AssertNoExistingUser(IDocumentOperations session, IUserAuth newUser,
            IUserAuth exceptForExistingUser = null)
        {
            if (newUser.UserName != null)
            {
                var existingUser = GetUserAuthByUserName(session, newUser.UserName);
                if (existingUser != null
                    && (exceptForExistingUser == null || existingUser.Id != exceptForExistingUser.Id))
                    throw new ArgumentException(ErrorMessages.UserAlreadyExistsFmt.LocalizeFmt(newUser.UserName.SafeInput()));
            }
            if (newUser.Email != null)
            {
                var existingUser = GetUserAuthByUserName(session, newUser.Email);
                if (existingUser != null
                    && (exceptForExistingUser == null || existingUser.Id != exceptForExistingUser.Id))
                    throw new ArgumentException(ErrorMessages.EmailAlreadyExistsFmt.LocalizeFmt(newUser.Email.SafeInput()));
            }
        }

        public IUserAuth CreateUserAuth(IUserAuth newUser, string passwordHash, string authDigest, string salt)
        {
            newUser.ValidateNewUser();

            return Execute(session =>
            {
                AssertNoExistingUser(session, newUser);

                newUser.PasswordHash = passwordHash;
                newUser.DigestHa1Hash = authDigest;
                newUser.Salt = salt;

                newUser.CreatedDate = DateTime.UtcNow;
                newUser.ModifiedDate = newUser.CreatedDate;

                session.Store((TUserAuth)newUser);

                newUser = session.Load<TUserAuth>(newUser.Id);
                return newUser;
            });
        }

        public IUserAuth CreateUserAuth(IUserAuth newUser, string password)
        {
            newUser.ValidateNewUser(password);
            newUser.PopulatePasswordHashes(password);
            return CreateUserAuth(newUser, newUser.PasswordHash, newUser.DigestHa1Hash, newUser.Salt);
        }

        public IUserAuth UpdateUserAuth(IUserAuth existingUser, IUserAuth newUser)
        {
            newUser.ValidateNewUser();

            return Execute(session =>
            {
                AssertNoExistingUser(session, newUser, existingUser);

                var userCopy = new
                {
                    existingUser.Id,
                    existingUser.PasswordHash,
                    existingUser.Salt,
                    existingUser.DigestHa1Hash,
                    existingUser.CreatedDate,
                };

                // populate properties from newUser
                existingUser.PopulateWith(newUser);

                // restore these original props
                existingUser.Id = userCopy.Id;
                existingUser.PasswordHash ??= userCopy.PasswordHash;
                existingUser.Salt ??= userCopy.Salt;
                existingUser.DigestHa1Hash = userCopy.DigestHa1Hash;
                existingUser.CreatedDate = userCopy.CreatedDate;
                existingUser.ModifiedDate = DateTime.UtcNow;

                session.Store((TUserAuth) existingUser);

                return existingUser;
            });
        }

        public IUserAuth UpdateUserAuth(IUserAuth existingUser, IUserAuth newUser, string password)
        {
            newUser.ValidateNewUser(password);

            return Execute(session =>
            {
                AssertNoExistingUser(session, newUser, existingUser);

                newUser.Id = existingUser.Id;
                newUser.PopulatePasswordHashes(password, existingUser);
                newUser.CreatedDate = existingUser.CreatedDate;
                newUser.ModifiedDate = DateTime.UtcNow;

                session.Store((TUserAuth) newUser);

                return newUser;
            });
        }

        public void DeleteUserAuth(string userAuthId)
        {
            Execute(session =>
            {
                var userId = int.Parse(userAuthId);

                session.Delete<TUserAuth>(userId);
                session.DeleteWhere<TUserAuthDetails>(x => x.UserAuthId == userId);
            });
        }

        public ICollection<string> GetRoles(string userAuthId)
        {
            var userAuth = GetUserAuth(userAuthId);
            return userAuth?.Roles;
        }

        public ICollection<string> GetPermissions(string userAuthId)
        {
            var userAuth = GetUserAuth(userAuthId);
            return userAuth?.Permissions;
        }

        public void GetRolesAndPermissions(string userAuthId, out ICollection<string> roles, out ICollection<string> permissions)
        {
            roles = GetRoles(userAuthId);
            permissions = GetPermissions(userAuthId);
        }

        public bool HasRole(string userAuthId, string role)
        {
            var userId = userAuthId.ToInt();
            return Execute(session =>
            {
                return session.Query<TUserAuth>().Any(x => x.Roles.Contains(role) && x.Id == userId);
            });
        }

        public bool HasPermission(string userAuthId, string permission)
        {
            var userId = userAuthId.ToInt();
            return Execute(session =>
            {
                return session.Query<TUserAuth>().Any(x => x.Permissions.Contains(permission) && x.Id == userId);
            });
        }

        public void AssignRoles(string userAuthId, ICollection<string> roles = null,
            ICollection<string> permissions = null)
        {
            Execute(session =>
            {
                var user = session.Load<TUserAuth>(userAuthId.ToInt());
                if (user == null)
                    return;

                var missingRoles = roles?.Where(role => !user.Roles.Contains(role)).ToArray();
                if (missingRoles?.Any() == true)
                    user.Roles.AddRange(missingRoles);

                var missingPermissins =
                    permissions?.Where(permission => !user.Permissions.Contains(permission)).ToArray();
                if (missingPermissins?.Any() == true)
                    user.Permissions.AddRange(missingPermissins);

                SaveUserAuth(session, user);
            });
        }

        public void UnAssignRoles(string userAuthId, ICollection<string> roles = null,
            ICollection<string> permissions = null)
        {
            Execute(session =>
            {
                var user = session.Load<TUserAuth>(userAuthId.ToInt());
                if (user == null)
                    return;

                roles.Each(role => user.Roles.Remove(role));
                permissions.Each(permission => user.Permissions.Remove(permission));

                SaveUserAuth(session, user);
            });
        }

        public void InitApiKeySchema()
        {
            // empty on purpose. This should be done by an extension method when initializing Marten store
        }

        public bool ApiKeyExists(string apiKey)
        {
            return Execute(session => session.Load<ApiKey>(apiKey) != null);
        }

        public ApiKey GetApiKey(string apiKey)
        {
            return Execute(session => session.Load<ApiKey>(apiKey));
        }

        public List<ApiKey> GetUserApiKeys(string userId)
        {
            return Execute(session => session.Query<ApiKey>().Where(x => x.UserAuthId == userId).ToList());
        }

        public void StoreAll(IEnumerable<ApiKey> apiKeys)
        {
            Execute(session =>
            {
                foreach (var key in apiKeys)
                {
                    session.Store(key);
                }
            });
        }
    }
}