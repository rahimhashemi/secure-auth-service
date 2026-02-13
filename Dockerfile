## ---- Build Stage ----
#FROM maven:3.9.9-eclipse-temurin-17 AS build
#WORKDIR /app
#
#COPY pom.xml .
#RUN mvn -B -e -DskipTests \
#  -Dmaven.repo.local=/root/.m2/repository \
#  dependency:go-offline
#
#COPY src ./src
#RUN mvn -B -e -DskipTests \
#  -Dmaven.repo.local=/root/.m2/repository \
#  package
#
## ---- Runtime Stage ----
#FROM eclipse-temurin:17-jre
#WORKDIR /app
#COPY --from=build /app/target/*.jar app.jar
#EXPOSE 8080
#ENTRYPOINT ["java","-jar","/app/app.jar"]

#--------------------------------------------------------------------
# build jar file outside of the docker
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
