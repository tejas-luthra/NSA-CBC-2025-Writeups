# NSA Codebreaker Challenge 2025 – Task 6: Crossing the Channel

**Competition:** NSA Codebreaker Challenge 2025  
**Category:** Vulnerability Research

---

## Challenge Description

This high visibility investigation has garnered a lot of agency attention. Due to your success, your team has designated you as the lead for the tasks ahead. Partnering with CNO and CYBERCOM mission elements, you work with operations to collect the persistent data associated with the identified Mattermost instance. Our analysts inform us that it was obtained through a one-time opportunity and we must move quickly as this may hold the key to tracking down our adversary! We have managed to create an account but it only granted us access to one channel. The adversary doesn't appear to be in that channel.

We will have to figure out how to get into the same channel as the adversary. If we can gain access to their communications, we may uncover further opportunity.

You are tasked with gaining access to the same channel as the target. The only interface that you have is the chat interface in Mattermost!

**Objective:** Submit a series of commands, one per line, given to the Mattermost server which will allow you to gain access to a channel with the adversary.

**Provided Materials:**
- `volumes.tar.gz` – Mattermost PostgreSQL database dump
- `user.txt` – User login credentials

---

## Methodology

### Phase 1: Database Setup

```bash
# Deploy PostgreSQL container
sudo docker run -d --name mattermost-db -e POSTGRES_HOST_AUTH_METHOD=trust postgres:13
# 8cf9fd53e5a5d3a282b67913ceef6601872a0223bfd9d8dc500d9f5260cac1ab

# Stop container to import data
sudo docker stop mattermost-db
# mattermost-db

# Import database dump
sudo docker cp volumes/db/var/lib/postgresql/data/. mattermost-db:/var/lib/postgresql/data/
# Successfully copied 55.9MB to mattermost-db:/var/lib/postgresql/data/

# Start database with imported data
sudo docker start mattermost-db
# mattermost-db

# Connect to database
sudo docker exec -it mattermost-db psql -U mmuser -d mattermost
```

### Phase 2: Database Reconnaissance

**Enumerate channels:**
```sql
SELECT id, name, displayname, type FROM channels;
```

**Output:**
```
             id             |                          name                          |  displayname  | type 
----------------------------+--------------------------------------------------------+---------------+------
 57jtt77s3irnpget9nkr87qicc | channel91657                                           | Channel 91657 | P
 sdx7b8wgbf8jdmkzu7gyan4ddh | 8qak34g75pr5dmnw3jpb3baj4c__t5getufsxtna3f8xug7hn4d9no |               | D
 yoi8tmzjqtf6b83yi9dxyrntzw | channel43608                                           | Channel 43608 | P
 woppdb5bu7g95pum17eez6uyno | channel20548                                           | Channel 20548 | P
 pmfojkfnfb8bmcdqseqezrk79h | channel82891                                           | Channel 82891 | P
 dca7uer33tdmzqrk5zgnitd9ww | channel13894                                           | Channel 13894 | P
 1pjak7hpdibgtxmbowe9skrriy | channel39699                                           | Channel 39699 | P
 8ho3w9ietbfpbjdfy1qejop6eh | channel48075                                           | Channel 48075 | P
 tfxijr13nifnxjzfop3jx7ndmc | channel83569                                           | Channel 83569 | P
 fjc7iob5g3drbdp3wm64e3ss7c | channel15215                                           | Channel 15215 | P
 tyizo11sw7yrjyebznuo3xrjgh | channel93775                                           | Channel 93775 | P
 34azkmfzkpdy3xggj1r959bz6y | channel86084                                           | Channel 86084 | P
 d7ur19y3wtyiimqntuyg49x6ne | channel18080                                           | Channel 18080 | P
 ije46piw1fnhfgwns3mx5he54r | channel87372                                           | Channel 87372 | P
 nctb48cdrbbj5cqdmsy9p4i1wh | channel38270                                           | Channel 38270 | P
 f4fu1fr6tif7xr9u8owftzqyhr | channel45032                                           | Channel 45032 | P
 6y9cprx3qiyzjchzzyfrhgouta | channel7928                                            | Channel 7928  | P
 9rucgb9rgb8o3ym5fqhg3e3gir | channel46447                                           | Channel 46447 | P
 6ja3a3bkyfrpbe1iawuootpffc | channel98336                                           | Channel 98336 | P
 pw79qw6maiyquc4gg1yqadxhnr | channel90552                                           | Channel 90552 | P
 se9mhxzs5p89zysqt6hngfcgnw | channel78495                                           | Channel 78495 | P
 gc49uwmcxpgo3k8fzx5d31u9uh | channel98388                                           | Channel 98388 | P
 4phreicckt8d3bgih9f77srrne | channel62162                                           | Channel 62162 | P
 qymr8z6skbncpjmjn7ewu6awey | channel64417                                           | Channel 64417 | P
 gmh7xgdxmfghmqnft4x51yhk6y | public                                                 | Public        | O
(25 rows)
```

**Channel types:**
- `O` = Open/Public (1 channel: "public")
- `P` = Private (24 channels)
- `D` = Direct messages

**Identify initial access:**
```sql
SELECT c.name, c.type 
FROM channels c 
JOIN channelmembers cm ON c.id = cm.channelid 
JOIN users u ON cm.userid = u.id 
WHERE u.username = 'mellowquiche61';
```

**Output:**
```
  name  | type 
--------+------
 public | O
(1 row)
```

Result: Only member of "public" channel initially.

### Phase 3: Understanding Negotiation

**Command format:**
```
# You do not add in your own user to this command
!nego <channel> <user1> <user2> <mod>
```

**Requirements:**
- Minimum 4 users
- All users must have access to current channel
- At least 4 users must NOT be in target channel
- Success grants access to target channel

### Phase 4: Iterative Path Discovery

**Negotiation Round 1:**
```sql
SELECT c.name, c.displayname,
  9 - (SELECT COUNT(*) 
   FROM channelmembers cm 
   WHERE cm.channelid = c.id 
   AND cm.userid IN (
     SELECT userid FROM channelmembers WHERE channelid = (SELECT id FROM channels WHERE name='public')
   )) as missing_public_members,
  (SELECT string_agg(u.username, ', ')
   FROM users u
   WHERE u.id IN (
     SELECT userid FROM channelmembers WHERE channelid = (SELECT id FROM channels WHERE name='public')
   )
   AND u.id NOT IN (
     SELECT userid FROM channelmembers WHERE channelid = c.id
   )) as available_users
FROM channels c
WHERE c.type = 'P'
AND 9 - (SELECT COUNT(*) 
     FROM channelmembers cm 
     WHERE cm.channelid = c.id 
     AND cm.userid IN (
       SELECT userid FROM channelmembers WHERE channelid = (SELECT id FROM channels WHERE name='public')
     )) >= 4
ORDER BY missing_public_members DESC, c.name;
```

**Output:**
```
     name     |  displayname  | missing_public_members |                           available_users                            
--------------+---------------+------------------------+----------------------------------------------------------------------
 channel15215 | Channel 15215 |                      4 | sugarylapwing47, mod_ashamedcrackers99, fondtoucan27, mellowquiche61
(1 row)
```

**Command:**
```
!nego channel15215 sugarylapwing47 fondtoucan27 mod_ashamedcrackers99
```

**Note:** Only 3 users needed (not including mellowquiche61 who is our user)

**Negotiation Round 2:**
```sql
WITH channel15215_after_nego AS (
  SELECT userid FROM channelmembers WHERE channelid = (SELECT id FROM channels WHERE name='channel15215')
  UNION
  SELECT id FROM users WHERE username IN ('mellowquiche61', 'fondtoucan27', 'mod_ashamedcrackers99', 'sugarylapwing47')
)
SELECT c.name, c.displayname,
  15 - (SELECT COUNT(*) 
   FROM channelmembers cm 
   WHERE cm.channelid = c.id 
   AND cm.userid IN (SELECT userid FROM channel15215_after_nego)
  ) as missing_members,
  (SELECT string_agg(u.username, ', ')
   FROM users u
   WHERE u.id IN (SELECT userid FROM channel15215_after_nego)
   AND u.id NOT IN (SELECT userid FROM channelmembers WHERE channelid = c.id)
  ) as available_users
FROM channels c
WHERE c.type = 'P'
AND c.name != 'channel15215'
AND 15 - (SELECT COUNT(*) 
     FROM channelmembers cm 
     WHERE cm.channelid = c.id 
     AND cm.userid IN (SELECT userid FROM channel15215_after_nego)
  ) >= 4
ORDER BY missing_members DESC
LIMIT 10;
```

**Output:**
```
     name     |  displayname  | missing_members |                             available_users                             
--------------+---------------+-----------------+-------------------------------------------------------------------------
 channel45032 | Channel 45032 |               4 | sugarylapwing47, culturedseahorse74, mod_spiritedbass59, mellowquiche61
(1 row)
```

**Command:**
```
!nego channel45032 sugarylapwing47 culturedseahorse74 mod_spiritedbass59
```

**Negotiation Round 3:**
```sql
WITH channel45032_after_nego AS (
  SELECT userid FROM channelmembers WHERE channelid = (SELECT id FROM channels WHERE name='channel45032')
  UNION
  SELECT id FROM users WHERE username IN ('sugarylapwing47', 'culturedseahorse74', 'mod_spiritedbass59', 'mellowquiche61')
)
SELECT c.name, c.displayname,
  (SELECT COUNT(*) FROM channel45032_after_nego) - (SELECT COUNT(*) 
   FROM channelmembers cm 
   WHERE cm.channelid = c.id 
   AND cm.userid IN (SELECT userid FROM channel45032_after_nego)
  ) as missing_members,
  (SELECT string_agg(u.username, ', ')
   FROM users u
   WHERE u.id IN (SELECT userid FROM channel45032_after_nego)
   AND u.id NOT IN (SELECT userid FROM channelmembers WHERE channelid = c.id)
  ) as available_users
FROM channels c
WHERE c.type = 'P'
AND c.name NOT IN ('channel15215', 'channel45032')
AND (SELECT COUNT(*) FROM channel45032_after_nego) - (SELECT COUNT(*) 
     FROM channelmembers cm 
     WHERE cm.channelid = c.id 
     AND cm.userid IN (SELECT userid FROM channel45032_after_nego)
  ) >= 4
ORDER BY missing_members DESC
LIMIT 10;
```

**Output:**
```
     name     |  displayname  | missing_members |                            available_users                            
--------------+---------------+-----------------+-----------------------------------------------------------------------
 channel91657 | Channel 91657 |               4 | cynicalpoultry0, culturedseahorse74, mod_bubblycake45, mellowquiche61
(1 row)
```

**Command:**
```
!nego channel91657 cynicalpoultry0 culturedseahorse74 mod_bubblycake45
```

**Negotiation Round 4:**
```sql
WITH channel91657_after_nego AS (
  SELECT userid FROM channelmembers WHERE channelid = (SELECT id FROM channels WHERE name='channel91657')
  UNION
  SELECT id FROM users WHERE username IN ('cynicalpoultry0', 'culturedseahorse74', 'mod_bubblycake45', 'mellowquiche61')
)
SELECT c.name, c.displayname,
  (SELECT COUNT(*) FROM channel91657_after_nego) - (SELECT COUNT(*) 
   FROM channelmembers cm 
   WHERE cm.channelid = c.id 
   AND cm.userid IN (SELECT userid FROM channel91657_after_nego)
  ) as missing_members,
  (SELECT string_agg(u.username, ', ')
   FROM users u
   WHERE u.id IN (SELECT userid FROM channel91657_after_nego)
   AND u.id NOT IN (SELECT userid FROM channelmembers WHERE channelid = c.id)
  ) as available_users
FROM channels c
WHERE c.type = 'P'
AND c.name NOT IN ('channel15215', 'channel45032', 'channel91657')
AND (SELECT COUNT(*) FROM channel91657_after_nego) - (SELECT COUNT(*) 
     FROM channelmembers cm 
     WHERE cm.channelid = c.id 
     AND cm.userid IN (SELECT userid FROM channel91657_after_nego)
  ) >= 4
ORDER BY missing_members DESC
LIMIT 10;
```

**Output:**
```
     name     |  displayname  | missing_members |                            available_users                             
--------------+---------------+-----------------+------------------------------------------------------------------------
 channel78495 | Channel 78495 |               4 | dreadfulfish3, cynicalpoultry0, mod_euphoricapricots31, mellowquiche61
(1 row)
```

**Command:**
```
!nego channel78495 dreadfulfish3 cynicalpoultry0 mod_euphoricapricots31
```

**Note:** After 4 successful negotiations, access was granted to the adversary's channel. The fifth round query was exploratory:

```sql
WITH channel78495_after_nego AS (
  SELECT userid FROM channelmembers WHERE channelid = (SELECT id FROM channels WHERE name='channel78495')
  UNION
  SELECT id FROM users WHERE username IN ('cynicalpoultry0', 'culturedseahorse74', 'mod_bubblycake45', 'mellowquiche61')
)
SELECT c.name, c.displayname,
  (SELECT COUNT(*) FROM channel78495_after_nego) - (SELECT COUNT(*) 
   FROM channelmembers cm 
   WHERE cm.channelid = c.id 
   AND cm.userid IN (SELECT userid FROM channel78495_after_nego)
  ) as missing_members,
  (SELECT string_agg(u.username, ', ')
   FROM users u
   WHERE u.id IN (SELECT userid FROM channel78495_after_nego)
   AND u.id NOT IN (SELECT userid FROM channelmembers WHERE channelid = c.id)
  ) as available_users
FROM channels c
WHERE c.type = 'P'
AND c.name NOT IN ('channel15215', 'channel45032', 'channel91657', 'channel78495')
AND (SELECT COUNT(*) FROM channel78495_after_nego) - (SELECT COUNT(*) 
     FROM channelmembers cm 
     WHERE cm.channelid = c.id 
     AND cm.userid IN (SELECT userid FROM channel78495_after_nego)
  ) >= 4
ORDER BY missing_members DESC
LIMIT 10;
```

**Output:**
```
     name     |  displayname  | missing_members |                               available_users                               
--------------+---------------+-----------------+-----------------------------------------------------------------------------
 channel20548 | Channel 20548 |               4 | sugarylapwing47, admin_pluckyfalcon61, mod_spiritedbass59, mellowquiche61
 channel82891 | Channel 82891 |               4 | brainycamel79, admin_pluckyfalcon61, mod_amusedzebra51, mellowquiche61
 channel13894 | Channel 13894 |               4 | admin_pluckyfalcon61, fondtoucan27, mod_ashamedcrackers99, mellowquiche61
 channel39699 | Channel 39699 |               4 | admin_pluckyfalcon61, fondtoucan27, artisticchamois96, mellowquiche61
 channel48075 | Channel 48075 |               4 | sugarylapwing47, admin_pluckyfalcon61, fondtoucan27, mellowquiche61
 channel83569 | Channel 83569 |               4 | admin_pluckyfalcon61, needfulstork74, mod_ashamedcrackers99, mellowquiche61
 channel93775 | Channel 93775 |               4 | admin_pluckyfalcon61, sadhare77, artisticchamois96, mellowquiche61
 channel86084 | Channel 86084 |               4 | brainycamel79, admin_pluckyfalcon61, needfulstork74, mellowquiche61
 channel18080 | Channel 18080 |               4 | admin_pluckyfalcon61, lyinglocust50, sadhare77, mellowquiche61
 channel38270 | Channel 38270 |               4 | culturedseahorse74, admin_pluckyfalcon61, mod_bubblycake45, mellowquiche61
(10 rows)
```

---

## Solution

**Complete negotiation sequence (4 commands):**
```
!nego channel15215 sugarylapwing47 fondtoucan27 mod_ashamedcrackers99
!nego channel45032 sugarylapwing47 culturedseahorse74 mod_spiritedbass59
!nego channel91657 cynicalpoultry0 culturedseahorse74 mod_bubblycake45
!nego channel78495 dreadfulfish3 cynicalpoultry0 mod_euphoricapricots31
```

**Access progression:**
```
Public (9 users) → channel15215 (15 users) → channel45032 (19 users) 
→ channel91657 (23 users) → channel78495 (adversary present)
```

**Key insight:** The `!nego` command automatically includes the user executing it (mellowquiche61), so only 3 additional users need to be specified per command, not 4.

---
