module Main where


import Options.Applicative
import System.Auth.Framework
import System.Auth.Native.Framework 
import Data.Monoid
       

-- Subcommands 
data Command = Init Bool
             | AddUser String String
             | DelUser String 
               deriving Show


-- Basic options
data AuthSystem = AuthSystem { username    :: String
                             , password    :: String
                             , store       :: String 
                             , subcommand  :: Command 
                             } deriving Show

-- Run the auth system
run :: AuthSystem -> IO () 
run (AuthSystem u p s (Init opt)) = do
               let av = getValidator :: AuthValidator NAuth 
                   un = parseUsername    av u
                   pw = validatePassword av p
               putStrLn $ "Initializing the system " ++ s
               initAuthFw un pw s :: IO NAuth
               putStrLn "Done"

run (AuthSystem u p s (AddUser nu np)) = do
                let av = getValidator :: AuthValidator NAuth
                    un = parseUsername    av u
                    pw = validatePassword av p
                    u' = parseUsername    av nu
                    p' = validatePassword av np
                result <- authUser un pw s 
                case result of 
                     Left   error -> putStrLn $ auMsg error
                     Right  auth  -> let task = unwrapTask auth (addUserTask :: AddUserTask NAuth)
                                     in case task of
                                          Left error   -> putStrLn $ auMsg error
                                          Right   fn   -> let a' = fn auth u' p'
                                                          in saveAuth a'

run (AuthSystem u p s (DelUser usr)) = do
                let av = getValidator :: AuthValidator NAuth
                    un = parseUsername    av u
                    pw = validatePassword av p
                    u' = parseUsername    av usr
                result <- authUser un pw s
                case result of 
                     Left   error -> putStrLn $ auMsg error
                     Right  auth  -> let task = unwrapTask auth (delUserTask :: DelUserTask NAuth)
                                     in case task of
                                        Left   error  -> putStrLn $ auMsg error 
                                        Right  fn     -> let a' = fn auth u'
                                                         in saveAuth a'

run (AuthSystem u p s _) = do 
                putStrLn "Not implemented"


-- Initialize the system
initCommandP :: Parser Command
initCommandP = Init 
               <$> flag False True ( long "overwrite"
                                   <> help "Overwrite existing store")

-- Add user
addUserCommandP = AddUser 
                  <$> strOption (  long     "newuser" 
                                <> metavar  "NEWUSERNAME"
                                <> help     "New username to add" )
                  <*> strOption (  long     "newpassword" 
                                <> metavar  "NEWPASSWORD"
                                <> help     "Password for the new user" )

-- Delete the user
delUserCommandP = DelUser 
                  <$> argument str (  metavar "USERNAME" )


-- Option parser
authSystemP :: Parser AuthSystem
authSystemP = AuthSystem 
              <$> strOption (  long    "user" 
                            <> metavar "USERNAME"
                            <> help    "User name for the system" )
              <*> strOption (  long    "password"
                            <> metavar "PASSWORD"
                            <> help    "Password for the username" )
              <*> strOption (  long    "store"
                            <> metavar "PATH"
                            <> help    "Path to auth database" )

              <*> subparser (  command  "init" 
                              (info initCommandP
                                    (progDesc "Initialize the system" ))

                            <> command  "add-user" 
                              (info addUserCommandP 
                                    (progDesc "Add user in the system"))

                            <> command  "del-user" 
                              (info delUserCommandP 
                                    (progDesc "Delete user from the system"))
                            )
                  

-- Run the parser
main = execParser opts >>= run
     where
        opts = info (helper <*> authSystemP)
                    (fullDesc
                    <> progDesc "Demonstrates the authorization system"
                    <> header   "auth - a sample application for System.Auth.Framwork" )

