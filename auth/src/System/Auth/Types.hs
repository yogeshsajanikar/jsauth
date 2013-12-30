{-# LANGUAGE FlexibleContexts          #-}
{-# LANGUAGE TypeFamilies              #-}
{-# LANGUAGE DeriveDataTypeable        #-}
{-# LANGUAGE RecordWildCards           #-}
module System.Auth.Types where

import Data.Dynamic
import Control.Exception 
import Text.ParserCombinators.Parsec.Rfc2822
import Data.Hash.MD5 
import Text.Parsec.Prim

data AuthError = AuthError { auMsg :: String } deriving (Eq, Ord, Show, Typeable)
instance Exception AuthError 


data Username  = Username String deriving Show
data Password  = Password String deriving Show
type Groupname = String
type AuthStore = String

class Validator a where


      -- | Validate the user name. 
      --  The default implementation checks for valid email address
      parseUsername :: a -> String -> Username
      parseUsername a uname = case parse address "" uname of
                                   Right addrs   -> Username $ nameAddr_addr $ head addrs
                                   otherwise     -> throw $ AuthError { auMsg = "Invalid user name " } 

      -- | validates the password, and calculates the hash
      --   The default implementation does not put any restriction.
      validatePassword :: a -> String -> Password
      validatePassword a pwd = Password $ md5s (Str pwd)


-- | Permission for a task/access
-- A permission is identified uniquely by its name. Each permission has
-- a name and its description
data Permission = Permission { pName :: String
                             , pDesc :: String }
                               deriving Show


-- Default administrator permissions
addUserPerm   = Permission "AddUser"    "Add User in the system"
delUserPerm   = Permission "DelUser"    "Delete user from the system"
lstUserPerm   = Permission "LstUser"    "List users in the system"
addGrpPerm    = Permission "AddGrp"     "Add group to the system"
lstGrpPerm    = Permission "LstGrp"     "List groups in the system"
delGrpPerm    = Permission "DelGrp"     "Delete group from the system"
addUsrGrpPerm = Permission "AddUsrGrp"  "Associate users with a group"
delUsrGrpPerm = Permission "DelUsrGrp"  "Remove users from the group"
addPermPerm   = Permission "AddPerm"    "Add permission in the system"
delPermPerm   = Permission "DelPerm"    "Delete permission from the system"
lstPermPerm   = Permission "LstPerm"    "Delete permission from the system"

adminPermissionsList :: [Permission]
adminPermissionsList =  [ addUserPerm
                        , delUserPerm
                        , lstUserPerm
                        , addGrpPerm
                        , lstGrpPerm
                        , delGrpPerm
                        , addUsrGrpPerm
                        , delUsrGrpPerm
                        , addPermPerm
                        , delPermPerm
                        , lstPermPerm ]



-- A task is a behavior idenitified by its name and given permission
class TaskDesc t where

      taskName :: t -> String

      permission :: t -> Permission
      

-- Authorized task represents an authorized task. Its behavior is described
-- later.
data AuthTask t = AuthTask { task :: t, authTaskName :: String, authPerm :: Permission }

instance TaskDesc (AuthTask t) where

         taskName AuthTask{..} = authTaskName

         permission AuthTask{..} = authPerm



-- | A Framework for authentication. Backends will implement this to
-- create an authentication framework
class Auth a where

     -- Validator is a related type to check the validitity of the
     -- username and password.
     type AuthValidator :: * -> * 

     -- Get the associated validator
     getValidator :: Validator (AuthValidator a) => AuthValidator a

     -- Initialize the system 
     initAuthFw :: Username -> Password -> AuthStore -> IO a

     -- Authorise the user, and return authorization
     authUser :: Username -> Password -> AuthStore -> IO (Either AuthError a)

     -- unwrap the task, if it is allowed for the current user
     unwrapTask :: a -> AuthTask b -> Either AuthError b




class Auth a => Administrator a where

      addUser :: a -> Username -> Password -> a
      delUser :: a -> Username -> a


      addGroup :: a -> Groupname -> a
      delGroup :: a -> Groupname -> a


      addUserToGroup   :: a -> Username -> Groupname -> a
      delUserFromGroup :: a -> Username -> Groupname -> a


      addPermission :: a -> Permission -> a
      delPermission :: a -> Permission -> a

      allowGroup  :: a -> Permission -> Groupname -> a
      denyGroup   :: a -> Permission -> Groupname -> a

      saveAuth :: a -> IO ()





