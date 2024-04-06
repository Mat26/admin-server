FROM eclipse-temurin:17-jdk-alpine
VOLUME /tmp
COPY target/*.jar admin-service.jar
ENTRYPOINT ["java","-jar","/admin-service.jar"]
EXPOSE 8086