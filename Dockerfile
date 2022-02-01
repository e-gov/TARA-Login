FROM tomcat:9.0-jdk11-openjdk

EXPOSE 8081

CMD ["catalina.sh", "run"]