# Authentication

Authenticate and verify users, devices and microservices.

### Build

This service uses maven. In order to build the project use:

```sh
$ mvn clean install -Dmaven.test.skip=true 
```

This generates a jar file, then run the following:

```sh
$ sudo docker-compose up --build -d
```

### Swagger

The service can be tested using swagger at:
[http://localhost:9100/auth/swagger-ui/index.html](http://localhost:9100/auth/swagger-ui/index.html)
Also there is a Postman collection with all the operations in the resources folder.


