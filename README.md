# CMEA
Confidential message exchange application (CMEA) in Java using pgcrypto.  
This application serves as a sample of a Java application that uses pgcrypto for encryption in PostgreSQL.  
The messages are stored encrypted in PostgreSQL and the intended recipient can decrypt and read them.  
The application uses symmetric as well as asymmetric encryption.  
Messages are encrypted and decrypted using a secret key.  
a) The public keys of both Alice and Bob are stored in database.  
b) When Alice makes Bob her friend, Alice generates a secret key (SK).  
c) The secret key (SK) is encrypted using Alice’s public key. This (MEK_S) will be used for message encryption.  
d) The secret key (SK) is also encrypted using Bob’s public key. This (MEK_R) will be used for message decryption.  
e) When Alice wants to send message to Bob, she first decrypts MEK_S using her private key to get SK.This makes sure that the sender is Alice, because only Alice can decrypt MEK_S using her private key.  
f) She then encrypts message using SK and saves cipher text in the database. This makes sure that only Bob can read them because only Bob can decrypt MEK_R using his private key.  
g) When Bob wants to read messages from Alice, he first decrypts MEK_R using his private key, to get SK.  
h) Bob then decrypts message sent by Alice using SK.  
  
The PostgreSQL schema is as follows:  
  
  DROP SCHEMA cmea CASCADE;  
  
  CREATE EXTENSION pgcrypto;
  
  CREATE SCHEMA cmea;  
  
  CREATE TABLE cmea.tbl_users(  
      u_id INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,  
      u_name varchar(255) NOT NULL UNIQUE,  
      u_public_key VARCHAR NOT NULL);  
      
  CREATE TABLE cmea.tbl_friends(  
      f_id INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,  
      f_from_u_id INT REFERENCES cmea.tbl_users(u_id),  
      f_to_u_id INT REFERENCES cmea.tbl_users(u_id),  
      f_mek_for_sending BYTEA NOT NULL,  
      f_mek_for_reading BYTEA NOT NULL,  
      UNIQUE (f_from_u_id, f_to_u_id));  
      
  CREATE TABLE cmea.tbl_messages(  
      m_id INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,  
      m_f_id INT REFERENCES cmea.tbl_friends(f_id),  
      m_message VARCHAR NOT NULL,  
      m_sent_on timestamp with time zone NOT NULL);  
    
    
  CREATE OR REPLACE FUNCTION cmea.getSenderID(m_f_id integer) RETURNS varchar AS $$  
  DECLARE uid VARCHAR(255);  
  BEGIN  
    SELECT u_id INTO uid FROM cmea.tbl_users, cmea.tbl_friends WHERE f_id = m_f_id AND f_from_u_id = u_id;  
    RETURn uid;  
  END; $$  
  LANGUAGE PLPGSQL;  
    
  CREATE OR REPLACE FUNCTION cmea.getSenderName(m_f_id integer) RETURNS varchar AS $$  
  DECLARE uname VARCHAR(255);  
  BEGIN  
    SELECT u_name INTO uname FROM cmea.tbl_users, cmea.tbl_friends WHERE f_id = m_f_id AND f_from_u_id = u_id;  
    RETURn uname;  
  END; $$  
  LANGUAGE PLPGSQL;  
    
  CREATE OR REPLACE FUNCTION cmea.addFriend(userid INTEGER, friendid INTEGER, secret_key TEXT)  
  RETURNS INTEGER AS $$  
  DECLARE user_pub_key TEXT;  
  DECLARE friend_pub_key TEXT;  
  BEGIN  
    SELECT u_public_key INTO user_pub_key FROM cmea.tbl_users WHERE u_id = userid;  
    SELECT u_public_key INTO friend_pub_key FROM cmea.tbl_users WHERE u_id = friendid;  
    
    INSERT INTO cmea.tbl_friends(f_from_u_id, f_to_u_id,  
              f_mek_for_sending, f_mek_for_reading) VALUES  
              (userid, friendid,  
              pgp_pub_encrypt(secret_key, dearmor(user_pub_key), 'cipher-algo=aes256'),  
              pgp_pub_encrypt(secret_key, dearmor(friend_pub_key), 'cipher-algo=aes256'));  
    RETURN 1;  
  END; $$  
  LANGUAGE PLPGSQL;  
    
  CREATE OR REPLACE FUNCTION cmea.sendMsg(userid INTEGER, friendid INTEGER, user_private_key TEXT, secret_msg TEXT)  
  RETURNS INTEGER AS $$  
    DECLARE fid INTEGER;  
    DECLARE fmek_for_sending BYTEA;  
    DECLARE mek_for_sending TEXT;  
    DECLARE encrypted_msg TEXT;  
  BEGIN  
    SELECT f_id , f_mek_for_sending INTO fid, fmek_for_sending  
    FROM cmea.tbl_friends WHERE f_from_u_id = userid AND f_to_u_id = friendid;  
    
    SELECT pgp_pub_decrypt(fmek_for_sending, dearmor(user_private_key), 'whatever', 'cipher-algo=aes256')  
    INTO mek_for_sending;  
    
    SELECT pgp_sym_encrypt(secret_msg, mek_for_sending) INTO encrypted_msg;  
    
    INSERT INTO cmea.tbl_messages (m_f_id, m_message, m_sent_on) VALUES(fid, encrypted_msg, now());  
    
    RETURN 1;  
  END; $$  
  LANGUAGE PLPGSQL;  
    
    
  CREATE OR REPLACE FUNCTION cmea.readMsg(userid INTEGER, friendid INTEGER, user_private_key TEXT)  
  RETURNS TABLE(m_id int, sender VARCHAR, sent_on timestamp with time zone, message TEXT)  
  LANGUAGE plpgsql  
  AS  
  $function$  
    DECLARE fid INTEGER;  
    DECLARE fmek_for_reading BYTEA;  
    DECLARE mek_for_reading TEXT;  
    DECLARE plain_text_msg TEXT;  
  BEGIN  
    SELECT f_id , f_mek_for_reading INTO fid, fmek_for_reading  
    FROM cmea.tbl_friends WHERE f_to_u_id = userid AND f_from_u_id = friendid;  
    
    SELECT pgp_pub_decrypt(fmek_for_reading, dearmor(user_private_key), 'whatever', 'cipher-algo=aes256')  
    INTO mek_for_reading;  
    
    RETURN QUERY SELECT m.m_id, cmea.getSenderName(fid), m.m_sent_on,  
           pgp_sym_decrypt(m.m_message::bytea, mek_for_reading)  
    FROM cmea.tbl_messages m WHERE m.m_f_id = fid;  
  END;  
  $function$;  
    
    
  build  
  mvn package  
  run  
  java -cp target/CMEA-1.0-SNAPSHOT.jar:  
             /home/abbas/.m2/repository/junit/junit/3.8.1/junit-3.8.1.jar:  
             /home/abbas/.m2/repository/org/postgresql/postgresql/42.2.5/postgresql-42.2.5.jar:  
             /home/abbas/Projects/pgconf_2020/didisoft/Library/bcpg-lw-jdk15on-1.59.jar:  
             /home/abbas/Projects/pgconf_2020/didisoft/Library/bcprov-lw-jdk15on-1.59.jar:  
             /home/abbas/Projects/pgconf_2020/didisoft/Library/pgplib-3.2.1.jar   
             com.edb.cmea.App read-messages
  
  We are using trial version of DidiSoft PGP Library for Java for Key generation.  
  The trial version is not provided as a maven repo.  
  Instead the pom.xml file adds dependency to the local file system.  
  Before building make sure that the file system paths given in the dependency are correct.  

Commands supported by the application  
  add-user  
  add-friend  
  send-messages  
  read-messages  
  
