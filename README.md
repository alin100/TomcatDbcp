加密 Tomcat8 DataSource 使用方式:

1. Import source code into eclipse as java project

2. add Apache Tomcat v8.0 Library 

3. export as executable jar, main-class use org.apache.tomcat.dbcp.dbcp.ext.Tool 
   use Jar name as **tomcat-dbcp-ext.jar**

4. move **tomcat-dbcp-ext.jar** into `CATALINA_HOME/lib` forlder

5. Confige Tomcat Datasource at `CATALINA_HOME/conf/context.xml`
sample at conf_context.xml

User Command line to test **encrypt/decrypt** password 

`java -jar tomcat-dbcp-ext.jar e/d p@ssw0rd`

