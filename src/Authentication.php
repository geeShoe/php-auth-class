<?php
namespace geeshoe\PhpAuthClass;

use geeshoe\dbClass\db;

class Authentication extends db
{
    public function verifyPassword($array)
    {
        $getThePasswordSql = 'SELECT `userPassword` FROM `authentication` WHERE `userName` = :authUserName';
        self::createSqlArray('update', $array);
        unset($this->values[':authPassword']);
        $query = self::fetch($getThePasswordSql, $this->values, \PDO::FETCH_ASSOC);

        if ($query) { //If query is true, then the username exists.
            if (password_verify($array['authPassword'], $query['userPassword'])) {
                return true;//Return true if the password supplied matches the db.
            }
        }
    }

    protected function checkUserName($array)
    {
        $sql = 'SELECT `userName` FROM `authentication` WHERE `userName` = :userName';
        self::createSqlArray('update', $array);
        $new = array(':userName'=> $this->values[':userName']);
        $test = array_intersect_key($this->values, $new);

        $dbUserName = self::fetch($sql, $test, \PDO::FETCH_ASSOC);
        if (empty($dbUserName)) {
            unset($this->insert);
            unset($this->values);
            return true;
        }
    }

    //Adds a new user to database
    public function createNewUser($array)
    {
        //Check if the passwords supplied match. If they do proceed, if not
        //tell the user the passwords don't match.
        if ($array['userPassword'] === $array['userPasswordVerify']) {
            //Call checkUserName, returns true if the username does not
            //exists in the database. If false, tell user the username supplied
            //is already taken.
            if (self::checkUserName($array)) {
                unset($array['userPasswordVerify']);//Remove verify password from the array of userSuppliedData
                $array['userPassword'] = password_hash($array['userPassword'], PASSWORD_DEFAULT);
                self::createSqlArray('insert', $array);
                $sql = self::createSqlInsertStatement('authentication');
                try {
                    //Insert the new user details into the database.
                    self::insert($sql, $this->values);
                    return true;
                } catch (\PDOException $exception) {
                    echo $exception->getMessage();
                }
            } else {
                echo "Username is already taken. Please select a new username.";
            }
        } else {
            echo "Passwords don't match.";
        }
    }
}
