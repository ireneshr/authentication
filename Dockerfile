FROM bigboards/java-8-armv7l
COPY "./target/*.jar" "app.jar"
ENTRYPOINT ["java","-jar","app.jar"]
