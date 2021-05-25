--User/DB creation
/*
create user 'micro-jcon'@'localhost' identified via mysql_native_password;

grant all privileges on *.* to 'micro-jcon'@'localhost' with grant option;

set password for 'micro-jcon'@'localhost' = password('w4miTXcHXCXL45pbUnTBeVg');

create database authentication;
*/

CREATE TABLE users (
    username VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(50),
    enabled TINYINT NOT NULL DEFAULT 1,
    PRIMARY KEY (username)
);

CREATE TABLE authorities (
    username VARCHAR(50) NOT NULL,
    authority VARCHAR(50) NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username)
);

CREATE UNIQUE INDEX ix_auth_username on authorities (username,authority);
