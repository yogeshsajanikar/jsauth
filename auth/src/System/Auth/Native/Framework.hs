{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE RecordWildCards           #-}

-- | Native framework for authorization. 
-- Users, Groups, and Permissions are managed much like unix
-- systems. Each user is represented 
module System.Auth.Native.Framework 
(
NValidator,
NAuth
)
where

import System.Auth.Native.Types
import qualified System.Auth.Native.Types as NativeT
import System.Auth.Types
import System.Auth.Framework
import Data.Monoid
import Data.Set


data NValidator a = NValidatorI deriving Show
instance Validator (NValidator a)

instance Auth NAuth where
         type AuthValidator = NValidator

         getValidator = NValidatorI

         initAuthFw (Username un) (Password pw) storepath = do 
                    let eAuth = mempty :: NAuth 
                        user  = NUser un pw
                        rAuth = addUser' user eAuth
                        fAuth = assocUserWithGroup user adminGroup rAuth
                    writeToStore fAuth storepath
                    return fAuth

         authUser (Username un) (Password pw) storepath = do
                  auth <- readFromStore storepath
                  let user = NUser un pw
                      rslt = authorizeUser user auth
                  case rslt of 
                       Just a  -> return $ Right a
                       Nothing -> return $ Left $ AuthError "Username or password not valid"

         
         unwrapTask auth atask = let authorizeTask = do
                                                        cu <- current auth
                                                        let np = mempty { perm = permission atask }
                                                        isUserPermitted cu np auth
                                 in
                                    case authorizeTask of 
                                         Nothing -> Left $ AuthError "Operation not allowed for current user"
                                         Just  u -> Right $ task atask


                    
                        
         
instance Administrator NAuth where 

         addUser auth (Username name) (Password pw) = let usr = NUser name pw
                                                      in  addUser' usr auth 


         delUser auth (Username name) = let usr = NUser name ""
                                        in  deleteUser usr auth 

         
         addGroup auth gname = let grp = mempty { groupid = gname }
                               in  NativeT.addGroup grp auth


         delGroup auth gname = let grp = mempty { groupid = gname }
                               in  NativeT.deleteGroup grp auth


         addUserToGroup auth (Username name) gname = 
                        let usr = NUser name ""
                            grp = mempty { groupid = gname }

                        in assocUserWithGroup usr grp auth

         delUserFromGroup auth@NAuth{..} (Username name) gname = 
                        let remove = do 
                                        fgrp <- lookupGroupF gname auth
                                        let lt  = gusers fgrp
                                            gs  = ltable lt
                                            ng  = delete name gs
                                            lt' = lt { ltable = ng }
                                        return $ fgrp { gusers = lt' }
                        in case remove of 
                           Nothing -> auth
                           Just  g -> NAuth current store users (insert g groups) permissions


         addPermission auth p = let np = mempty { perm = p }
                                in NativeT.addPermission np auth


         delPermission auth p = let np = mempty { perm = p }
                                in NativeT.deletePermission np auth

         allowGroup auth p g = let np = mempty  { perm = p }
                                   gp = mempty  { groupid = g }

                               in permitGroup np gp auth

                               
         denyGroup auth@NAuth{..} p g = 
                        let deny = do 
                                        let prm = mempty { perm = p }
                                        fprm <- lookupPermissionF prm auth
                                        let lt  = pgroups fprm
                                            gs  = ltable lt
                                            ng  = delete g gs
                                            lt' = lt { ltable = ng }
                                        return $ fprm { pgroups = lt' }
                        in case deny of 
                           Nothing -> auth
                           Just  p -> NAuth current store users groups (insert p permissions)


         saveAuth auth@NAuth{..} = writeToStore auth store

