{-# LANGUAGE RecordWildCards           #-}

module System.Auth.Framework
(
Username, 
Password, 
AuthStore, 
Validator(parseUsername, validatePassword),
Permission,
permissionName,
permissionDesc,
Auth(getValidator, initAuthFw, authUser, unwrapTask),
AuthValidator,
AuthTask,
AuthError(..),
Administrator(saveAuth),
AddUserTask,
addUserTask
)

where

import Control.Exception
import System.Auth.Types


-- Get the name of the permission
permissionName :: Permission -> String
permissionName Permission {..} = pName

-- Get the description of the permission
permissionDesc :: Permission -> String
permissionDesc Permission {..} = pDesc


type AddUserTask a = AuthTask (a -> Username -> Password -> a) 

addUserTask :: Administrator a => AddUserTask a
addUserTask = AuthTask { task = addUser, authTaskName = "Add User", authPerm = addUserPerm }

type DelUserTask a = AuthTask (a -> Username -> a )

delUserTask :: Administrator a => DelUserTask a
delUserTask = AuthTask { task = delUser, authTaskName = "Delete User", authPerm = delUserPerm }

type GroupTask a = AuthTask (a -> Groupname -> a)

addGroupTask :: Administrator a => GroupTask a
addGroupTask = AuthTask { task = addGroup, authTaskName = "Add Group", authPerm = addGrpPerm }


delGroupTask :: Administrator a => GroupTask a
delGroupTask = AuthTask { task = delGroup, authTaskName = "Delete Group", authPerm = delGrpPerm }



