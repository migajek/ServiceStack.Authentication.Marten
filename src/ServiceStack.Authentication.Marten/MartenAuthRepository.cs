using System;
using System.Linq;
using System.Collections.Generic;
using ServiceStack.Auth;
using Marten;

namespace ServiceStack.Authentication.Marten
{
    public class MartenAuthRepository : MartenAuthRepository<UserAuth, UserAuthDetails>
    {
        public MartenAuthRepository(IDocumentStore documentStore, IHashProvider hashProvider) : base(documentStore, hashProvider)
        {
        }
    }    

    public class MartenAuthRepository<TUserAuth, TUserAuthDetails> : IUserAuthRepository, IManageRoles
        where TUserAuth : class, IUserAuth
        where TUserAuthDetails : class, IUserAuthDetails
    {
        private readonly IDocumentStore _documentStore;
        private readonly IHashProvider _hashProvider;

        public MartenAuthRepository(IDocumentStore documentStore, IHashProvider hashProvider)
        {
            _documentStore = documentStore;
            _hashProvider = hashProvider;
        }


        internal void Execute(Action<IDocumentSession> fn)
        {
            using (var session = _documentStore.OpenSession())
            {
                fn(session);
            }
        }

        internal T Execute<T>(Func<IDocumentSession, T> fn)
        {           
            using (var session = _documentStore.OpenSession())
            {
                return fn(session);
            }
        }

        public void LoadUserAuth(IAuthSession session, IAuthTokens tokens)
        {
            if (session == null)
                throw new ArgumentNullException(nameof(session));

            var userAuth = GetUserAuth(session, tokens);
            LoadUserAuth(session, userAuth);
        }

        private void LoadUserAuth(IAuthSession session, IUserAuth userAuth)
        {
            session.PopulateSession(userAuth,
                GetUserAuthDetails(session.UserAuthId).ConvertAll(x => (IAuthTokens) x));
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
                session.SaveChanges();
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
                session.SaveChanges();
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

        public TUserAuth GetUserAuthByUserName(IDocumentSession session, string userNameOrEmail)
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
                session.SaveChanges();
            });
        }

        private void SaveUserAuth(IDocumentSession session, IUserAuth userAuth)
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

            if (_hashProvider.VerifyHashString(password, userAuth.PasswordHash, userAuth.Salt))
            {
                this.RecordSuccessfulLogin(userAuth);
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

            var digestHelper = new DigestAuthFunctions();
            if (digestHelper.ValidateResponse(digestHeaders, privateKey, nonceTimeOut, userAuth.DigestHa1Hash, sequence))
            {
                this.RecordSuccessfulLogin(userAuth);
                return true;
            }

            this.RecordInvalidLoginAttempt(userAuth);

            userAuth = null;
            return false;
        }

        protected virtual void AssertNoExistingUser(IDocumentSession session, IUserAuth newUser,
            IUserAuth exceptForExistingUser = null)
        {
            if (newUser.UserName != null)
            {
                var existingUser = GetUserAuthByUserName(session, newUser.UserName);
                if (existingUser != null
                    && (exceptForExistingUser == null || existingUser.Id != exceptForExistingUser.Id))
                    throw new ArgumentException(string.Format(ErrorMessages.UserAlreadyExistsTemplate1, newUser.UserName));
            }
            if (newUser.Email != null)
            {
                var existingUser = GetUserAuthByUserName(session, newUser.Email);
                if (existingUser != null
                    && (exceptForExistingUser == null || existingUser.Id != exceptForExistingUser.Id))
                    throw new ArgumentException(string.Format(ErrorMessages.EmailAlreadyExistsTemplate1, newUser.Email));
            }
        }

        public IUserAuth CreateUserAuth(IUserAuth newUser, string password)
        {
            newUser.ValidateNewUser(password);

            return Execute(session =>
            {
                AssertNoExistingUser(session, newUser);

                _hashProvider.GetHashAndSaltString(password, out var hash, out var salt);
                var digestHelper = new DigestAuthFunctions();
                newUser.DigestHa1Hash = digestHelper.CreateHa1(newUser.UserName, DigestAuthProvider.Realm, password);
                newUser.PasswordHash = hash;
                newUser.Salt = salt;
                newUser.CreatedDate = DateTime.UtcNow;
                newUser.ModifiedDate = newUser.CreatedDate;

                session.Store((TUserAuth) newUser);

                newUser = session.Load<TUserAuth>(newUser.Id);
                session.SaveChanges();
                return newUser;
            });
        }

        public IUserAuth UpdateUserAuth(IUserAuth existingUser, IUserAuth newUser)
        {
            newUser.ValidateNewUser();

            return Execute(session =>
            {
                AssertNoExistingUser(session, newUser, existingUser);

                newUser.Id = existingUser.Id;
                newUser.PasswordHash = existingUser.PasswordHash;
                newUser.Salt = existingUser.Salt;
                newUser.DigestHa1Hash = existingUser.DigestHa1Hash;
                newUser.CreatedDate = existingUser.CreatedDate;
                newUser.ModifiedDate = DateTime.UtcNow;

                session.Store((TUserAuth) newUser);
                session.SaveChanges();

                return newUser;
            });
        }

        public IUserAuth UpdateUserAuth(IUserAuth existingUser, IUserAuth newUser, string password)
        {
            newUser.ValidateNewUser(password);

            return Execute(session =>
            {
                AssertNoExistingUser(session, newUser, existingUser);

                var hash = existingUser.PasswordHash;
                var salt = existingUser.Salt;
                if (password != null)
                    _hashProvider.GetHashAndSaltString(password, out hash, out salt);

                // If either one changes the digest hash has to be recalculated
                var digestHash = existingUser.DigestHa1Hash;
                if (password != null || existingUser.UserName != newUser.UserName)
                    digestHash = new DigestAuthFunctions().CreateHa1(newUser.UserName, DigestAuthProvider.Realm,
                        password);

                newUser.Id = existingUser.Id;
                newUser.PasswordHash = hash;
                newUser.Salt = salt;
                newUser.DigestHa1Hash = digestHash;
                newUser.CreatedDate = existingUser.CreatedDate;
                newUser.ModifiedDate = DateTime.UtcNow;

                session.Store((TUserAuth) newUser);
                session.SaveChanges();

                return newUser;
            });
        }
        
        public void DeleteUserAuth(string userAuthId)
        {
            Execute(session =>
            {
                var userId = int.Parse(userAuthId);

                session.Delete<TUserAuth>(userId);

                var userAuthDetails = session.Query<TUserAuthDetails>().Where(x => x.UserAuthId == userId).ToList();
                userAuthDetails.ForEach(userAuthDetail => session.Delete<TUserAuthDetails>(userAuthDetail));
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
                session.SaveChanges();
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
                session.SaveChanges();
            });
        }
    }
}