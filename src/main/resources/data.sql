-- Bcrypt Password generator & checker
-- https://bcrypt-generator.com/

insert into users values ('Irene', '$2y$18$e6vunphVC5BocMhUFWn04.0rQtlBl0f/8.3w8zePHTrLnOSRzLMpi', 'dummy', 1);
insert into authorities values ('Irene', 'ROLE_ADMIN');

insert into users values ('Mauricio', '', '', 1);
insert into authorities values ('Mauricio', 'ROLE_ADMIN');
