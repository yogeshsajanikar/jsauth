jsauth
======

A simple authorisation system.



# Implementation

It has native support for the user/group/permission management. The
native implementation uses JSON to store the user data. However, it is
possible to implement other backends by instantiating class
System.Auth.Framework.Auth.

A sample command line application is implemented as a testbed for
testing the system. You can find it at app/Main.hs


# Users, Groups, Permissions and Tasks

## User

A user is identified by his/her email id. A user can be part of one or
many groups.


## Group

Each group in the system has a unique name. Each group can hold a set
of users.

### Important Groups

#### Administrators
The user which is used to initialize the system becomes the
administrator. Administrators have special privilages to add, delete
users etc. This is explained in the permissions section.

#### Default
Each user, when added to the system, becomes part of default group
(name "Default"). A default group may or may not have any privilages.

## Permission
A permission is a unique name and its description. A permission holds
a set of groups. Each member group of the permission is allowed access 
to a set of tasks.

A permission is defined as

``` haskell
data Permission = Permission { pName :: String
                             , pDesc :: String }
```

## Task
A task is an activity that can be carried by a user only if a permission
is granted to the user. A task is defined as

``` haskell
class TaskDesc t where

      taskName :: t -> String

      permission :: t -> Permission

data AuthTask t = AuthTask { task :: t, authTaskName :: String, authPerm :: Permission }

```
Each task has a name, and a permission associated with it. To run the
task, the user unwraps the task, and can run the computation inside
the task. For example: to run the AddUserTask (to add the user to the system)

``` haskell
let task = unwrapTask auth (addUserTask :: AddUserTask NAuth)
in case task of
        Left error   -> putStrLn $ auMsg error
        Right   fn   -> let a' = fn auth u' p' -- gained an access, add user here
                                 in saveAuth a'

```

# Commmand Line Application

Command line application 'auth' currently supports following options

## Basic options

``` bash
auth - a sample application for System.Auth.Framwork

Usage: auth --user USERNAME --password PASSWORD --store PATH COMMAND
  Demonstrates the authorization system

Available options:
  -h,--help                Show this help text
  --user USERNAME          User name for the system
  --password PASSWORD      Password for the username
  --store PATH             Path to auth database

Available commands:
  init                     Initialize the system
  add-user                 Add user in the system

```

The commands are authorized by the username and password supplied above.

## Commands

### Initialize the system
```
Usage: auth init [--overwrite]
  Initialize the system

Available options:
  --overwrite              Overwrite existing store

```

### Add the user
Add the user 

```
Usage: auth add-user --newuser NEWUSERNAME --newpassword NEWPASSWORD
```

### Delete the user
Delete the given user

```
Usage: auth del-user username
```

