{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE FlexibleInstances #-}
module System.Auth.Native.Types where

import Data.Set hiding(map)
import qualified Data.Set as S
import Data.Aeson
import Control.Exception
import Control.Applicative
import Control.Monad
import System.Auth.Types
import qualified Data.ByteString.Lazy as B
import Data.Monoid


-- We would like to avoid the cyclic dependency in the data structure so that
-- the serialization/deserialization can be done. The lookup table is used as a 
-- foreign key 
data LookupTable key container value = LookupTable { ltable  :: Set key 
                                                   , lookupF :: key -> container -> Maybe value }

instance Show key => Show (LookupTable key container value) where

         show LookupTable{..} = "LookupTable " ++ (show ltable)


-- User is represented by its id, and password (md5hash)
data NUser  = NUser  { userid   :: String
                     , password :: String }
                       deriving (Show) 

-- A group has a group id and a set of users for every group. Each set is 
-- represnted by a set of userids pointing to the user table.
data NGroup = NGroup { groupid :: String
                     , gusers  :: LookupTable String NAuth NUser }
                       deriving (Show)

-- Each permission has a name, and description. Each permission is associated
-- with a set of groups.
data NPerm  = NPerm  { perm    :: Permission
                     , pgroups :: LookupTable String NAuth NGroup }
                       deriving (Show)

-- Eq and Ord instances for NUser, NGroup and NPerm. We consider only id, and 
-- ignore other contents. It means that if we can override the value if we insert 
-- in the set with the same key.

instance Eq NUser where
         (==) u1 u2 = (userid u1) == (userid u2)

instance Ord NUser where
         compare u1 u2 = compare (userid u1) (userid u2)

instance Eq NGroup where
         (==) g1 g2 = (groupid g1) == (groupid g2)

instance Ord NGroup where
         compare g1 g2 = compare (groupid g1) (groupid g2)

instance Eq NPerm where
         (==) p1 p2 = (pName $ perm p1) == (pName $ perm p2)

instance Ord NPerm where
         compare p1 p2 = (pName $ perm p1) `compare` (pName $ perm p2)


-- JSON Support for reading and writing the authorization system
instance ToJSON NUser where
         toJSON NUser{..} = object [ "userid"   .= userid
                                   , "password" .= password ]

instance FromJSON NUser where
         parseJSON (Object v) = NUser           <$>
                                v .: "userid"   <*>
                                v .: "password"

         parseJSON _          = mzero

instance ToJSON key => ToJSON (LookupTable key container value) where
         toJSON LookupTable{..} = object [ "ltable" .= ltable ]


-- For LookupTable we create special instance so that we can associate
-- right lookup function with it.
createUserLookupTable :: Set String -> LookupTable String NAuth NUser 
createUserLookupTable keys = LookupTable keys lookupUserF

instance FromJSON (LookupTable String NAuth NUser) where
         parseJSON (Object v) = createUserLookupTable <$>
                                v .: "ltable"

createGroupLookupTable :: Set String -> LookupTable String NAuth NGroup
createGroupLookupTable keys = LookupTable keys lookupGroupF

instance FromJSON (LookupTable String NAuth NGroup) where
         parseJSON (Object v) = createGroupLookupTable <$>
                                v .: "ltable"

instance ToJSON NGroup where
         toJSON NGroup{..} = object [ "groupid" .= groupid
                                    , "users"   .= gusers ]


instance FromJSON NGroup where
         parseJSON (Object v) = NGroup  <$>
                                v .: "groupid"  <*>
                                v .: "users"   

         parseJSON _          = mzero


instance ToJSON Permission where
         toJSON Permission{..} = object [ "permissionid"  .= pName
                                        , "description"   .= pDesc ]
         

instance FromJSON Permission where
         parseJSON (Object v) = Permission <$>
                                v .: "permissionid" <*>
                                v .: "description"

         parseJSON _ = mzero

instance ToJSON NPerm where
         toJSON NPerm{..} = object [ "permission" .= perm 
                                   , "groups"     .= pgroups ]

instance FromJSON NPerm where
         parseJSON (Object v) = NPerm <$>
                                v .: "permission" <*>
                                v .: "groups"

         parseJSON _ = mzero


-- Authorization system is a set of users, group and permissions
-- groups keep a reference to users, and permissions keep a reference
-- to groups
data NAuth = NAuth { current     :: Maybe NUser
                   , store       :: FilePath
                   , users       :: Set NUser
                   , groups      :: Set NGroup
                   , permissions :: Set NPerm }
                     deriving Show

instance ToJSON NAuth where
         toJSON NAuth{..} = object [ "users"       .= users
                                   , "groups"      .= groups
                                   , "permissions" .= permissions ]


instance FromJSON NAuth where
         parseJSON (Object v) = NAuth Nothing "" <$>
                                v .: "users" <*>
                                v .: "groups" <*>
                                v .: "permissions"


         parseJSON _ = mzero


-- authorization system has default groups Administrator, and Default
-- The Default group might have basic permissions associated with it.
adminGroup   = mempty { groupid = "Administrator" }
defaultGroup = mempty { groupid = "Default" }


-- write the system to JSON
writeToStore :: NAuth -> FilePath -> IO ()
writeToStore au path = do 
            B.writeFile path $ encode au


readFromStore :: FilePath -> IO NAuth
readFromStore path = do
              bs <- B.readFile path
              case decode bs :: Maybe NAuth of 
                   Nothing  -> throw $ AuthError "Error reading authorization store"
                   Just au  -> return au { store = path }


-- 
defaultGroups :: [NGroup]
defaultGroups =  [adminGroup, defaultGroup]


adminPermissions admGrp = let gtable      = createGroupLookupTable $ singleton $ groupid admGrp
                              permissions = map (\p -> NPerm p gtable) adminPermissionsList
                          in  fromList permissions

-- Define lookup table with undefined lookup
instance Ord k => Monoid (LookupTable k c v) where
         mempty = LookupTable mempty undefined

         mappend g1 g2 = let ltable' = mappend (ltable g1) (ltable g2)
                         in LookupTable ltable' $ lookupF g1


-- Define NGroup with lookup table for users
instance Monoid NGroup where 

         mempty = NGroup "" lt 
                where lt = mempty { lookupF = lookupUserF }

         mappend g1 g2 = case groupid g2 of 
                              ""        ->  NGroup (groupid g1)  gusers'
                              otherwise ->  NGroup (groupid g2)  gusers'
                 where
                        gusers' = (mappend (gusers g1) (gusers g2))


instance Monoid NPerm where
         mempty = NPerm { perm = Permission "" "", pgroups = lt } 
                where
                        lt = mempty { lookupF = lookupGroupF }
         

         mappend p1 p2 = case pName $ perm p2 of
                              ""        -> NPerm (perm p1) pgroups'
                              otherwise -> NPerm (perm p2) pgroups'
                 where
                        pgroups' = mappend (pgroups p1) (pgroups p2)


-- Define NAuth with default groups (admin, and default) and default 
-- permissions
instance Monoid NAuth where

         mempty = 
                  let defaultGroupSet  = fromList defaultGroups
                      Just admGroup    = Data.Set.lookupLE adminGroup defaultGroupSet
                  in 
                     NAuth { current     = Nothing
                           , store       = ""
                           , users       = mempty 
                           , groups      = defaultGroupSet
                           , permissions = adminPermissions admGroup
                           }

         -- Caution users will get overridden, may land in a non-usable state
         mappend au bu = NAuth { current     = cu
                               , store       = sp
                               , users       = mappend (users au)       (users bu)
                               , groups      = mappend (groups au)      (groups bu)
                               , permissions = mappend (permissions au) (permissions bu)
                               }
                 where cu = case current bu of 
                                 Nothing -> current au
                                 u       -> u
                       sp = case store bu of
                                 "" -> store au
                                 p  -> p



-- Lookup function for user 
lookupUserF :: String -> NAuth -> Maybe NUser
lookupUserF key auth = case lookupLE user (users auth) of
                            Nothing -> Nothing
                            Just  u -> case userid u == key of
                                            True   -> Just u
                                            False  -> Nothing

            where
                user = NUser key ""

-- Lookup function for group
lookupGroupF :: String -> NAuth -> Maybe NGroup
lookupGroupF key auth = case lookupLE group (groups auth) of
                             Nothing -> Nothing
                             Just  g -> case groupid g == key of
                                             True  -> Just g
                                             False -> Nothing

             where
                group = mempty { groupid = key }


lookupPermissionF :: NPerm -> NAuth -> Maybe NPerm
lookupPermissionF perm auth@NAuth{..} = do 
                                           found <- lookupLE perm permissions
                                           case perm == found of
                                                True  -> Just found
                                                False -> Nothing
                                           

-- insert key in the lookup table
insertKey :: Ord k => k -> LookupTable k c v -> LookupTable k c v
insertKey k t@LookupTable{..} = let ltable' = insert k ltable
                                in LookupTable ltable' lookupF

-- Add user to the group, return the modified group
addUserToGroup' :: NUser -> NGroup -> NGroup 
addUserToGroup' user@NUser{..} grp@NGroup{..} = NGroup groupid (insertKey userid gusers)


-- Add user to the group, return the modified group
addGroupToPerm :: NGroup -> NPerm -> NPerm
addGroupToPerm grp@NGroup{..} NPerm{..}= NPerm perm (insertKey groupid pgroups)


-- Get default group, every user is a default user
getDefaultGroup auth = case lookupGroupF (groupid defaultGroup) auth of
                            Nothing      -> throw $ AuthError "Default group not found"
                            Just dg      -> dg


-- Add user to the authorization system, and add the default group to it.
addUser' :: NUser -> NAuth -> NAuth
addUser' user auth@NAuth{..} = case lookupUserF (userid user) auth of 
                                             Nothing     -> newauth
                                             Just u      -> auth
        where
                newauth       = NAuth current store newusers newgroups permissions 
                newusers      = insert user users
                defaultGroup  = addUserToGroup' user (getDefaultGroup auth)
                newgroups     = insert defaultGroup groups


-- Add a group to the system
addGroup :: NGroup -> NAuth -> NAuth 
addGroup grp auth@NAuth{..} = case lookupGroupF (groupid grp) auth of 
                         Nothing  ->  newauth
                         Just  g  ->  auth
         where
                newauth      = NAuth current store users newgroups permissions
                newgroup     = mempty { groupid = groupid grp }
                newgroups    = insert newgroup groups


-- Associate user with a group
assocUserWithGroup :: NUser -> NGroup -> NAuth -> NAuth 
assocUserWithGroup usr grp auth = let assoc = do 
                                                 fuser <- lookupUserF   (userid  usr) auth
                                                 fgrp  <- lookupGroupF  (groupid grp) auth
                                                 let ngrp = addUserToGroup' fuser fgrp
                                                     grps = groups auth
                                                 return $ NAuth (current auth) (store auth) (users auth) (insert ngrp grps) (permissions auth)
                                  in 
                                     case assoc of 
                                          Nothing -> auth
                                          Just  a -> a

-- List users in the system
listUsers :: NAuth -> [NUser]
listUsers = toList . users


-- List groups in the system
listGroups :: NAuth -> [NGroup]
listGroups = toList . groups

-- List the permissions in the system
listPermissions :: NAuth -> [NPerm]
listPermissions = toList . permissions


-- List the groups that the user belongs to 
listUserGroups :: NUser -> NAuth -> [NGroup]
listUserGroups usr auth = let uid = userid usr
                              appendgrp g gs = case member uid $ ltable $ gusers g of
                                                    True   -> g:gs
                                                    False  -> gs
                          in
                              S.foldr' appendgrp [] (groups auth)


-- Delete the given user from the system, and also from the associated groups
deleteUser :: NUser -> NAuth -> NAuth
deleteUser usr auth@NAuth{..} = NAuth current store nusers ngroups permissions
           where
                uid       = userid usr
                nusers    = delete usr users
                ltable' g = delete uid $ ltable $ gusers g
                ngroups   = S.map (\g -> NGroup (groupid g) mempty{ltable=ltable' g}) groups


-- Delete the group from the system, and also from the permissions groups
deleteGroup :: NGroup -> NAuth -> NAuth 
deleteGroup grp auth@NAuth{..} = NAuth current store users ngroups npermissions
            where 
                gid          = groupid grp
                ngroups      = delete grp groups
                pgroups' p   = LookupTable { ltable = delete gid $ ltable $ pgroups p, lookupF = lookupGroupF }
                npermissions = S.map (\p -> NPerm (perm p) (pgroups' p)) permissions


-- Add a new permission to the system
addPermission :: NPerm -> NAuth -> NAuth 
addPermission perm auth@NAuth{..} = NAuth current store users groups npermissions
              where
                npermissions = insert perm permissions

-- Delete the permission from the system, does not affect users and groups
deletePermission :: NPerm -> NAuth -> NAuth
deletePermission perm auth@NAuth{..} = NAuth current store users groups npermissions 
                 where
                        npermissions = delete perm permissions


-- Authorize the user
authorizeUser :: NUser -> NAuth -> Maybe NAuth
authorizeUser usr auth@NAuth{..} = do 
                                      fuser <- lookupUserF (userid usr) auth
                                      case (password fuser) == (password usr) of
                                           True  -> Just $ auth { current = Just fuser }
                                           False -> Nothing
                                      
                                      
isUserPermitted :: NUser -> NPerm -> NAuth -> Maybe NUser
isUserPermitted usr perm auth@NAuth{..} = do
                    fuser <- lookupUserF (userid usr) auth
                    fperm <- lookupPermissionF perm   auth
                    let pgs  = ltable $ pgroups fperm
                    case S.foldr isMember False pgs of
                         True  -> Just fuser
                         False -> Nothing
                where
                        isMember g True  = True 
                        isMember g False = case lookupGroupF g auth of
                                                Nothing  -> False
                                                Just  g' -> member (userid usr) $ ltable $ gusers g'
                                 
                    
                        

permitGroup :: NPerm -> NGroup -> NAuth -> NAuth 
permitGroup prm grp auth =
            let permit = do
                                fgrp  <- lookupGroupF       (groupid grp) auth
                                fprm  <- lookupPermissionF  prm auth 
                                let nprm = addGroupToPerm fgrp fprm 
                                    prms = permissions auth
                                return $ NAuth (current auth) (store auth) (users auth) (groups auth) (insert nprm prms)
            in 
               case permit of 
                    Nothing -> auth
                    Just  a -> a

